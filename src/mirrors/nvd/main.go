package nvd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
	"github.com/schollz/progressbar/v3"
	"github.com/sirupsen/logrus"
	"github.com/uptrace/bun"
)

var logger = logrus.StandardLogger()

// apiURLTemplate is the NVD CVE API, with page size, start index and modified-date window.
var apiURLTemplate = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=%d&startIndex=%d&lastModStartDate=%s&lastModEndDate=%s"

// fullURLTemplate is the same API with no date window, so every CVE is returned.
var fullURLTemplate = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=%d&startIndex=%d"

type NVDStats struct {
	TotalResults int `json:"totalResults"`
}

type Config struct {
	Key  string `json:"_key"`
	Last string `json:"last"`
}

// Update syncs CVEs modified since the NVD watermark, in windows of at most 120 days.
// The watermark moves only after every window succeeded.
func Update(db *bun.DB, db_config *bun.DB) error {
	return sourcesync.Run(db, knowledge.SourceNVD, func() (time.Time, error) {
		return syncWindows(db, db_config)
	})
}

// syncWindows returns the end of the last window, or the zero time if any window failed.
func syncWindows(db *bun.DB, db_config *bun.DB) (time.Time, error) {
	log.Println("Start updating NVD")

	since, err := sourcesync.Watermark(db, knowledge.SourceNVD)
	if err != nil {
		return time.Time{}, err
	}
	since = since.UTC()
	log.Println("Last date: ", since)
	fullFetch := since.IsZero()

	apiKey := os.Getenv("NVD_API_KEY")
	if apiKey == "" {
		log.Println("NVD_API_KEY environment variable not set")
	}

	maxRequests := 50
	rateLimiterSleep := 30 * time.Second / time.Duration(maxRequests)
	if apiKey == "" {
		maxRequests = 5
		rateLimiterSleep = 60 * time.Second / time.Duration(maxRequests)
	}
	rateLimiter := make(chan struct{}, maxRequests)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case rateLimiter <- struct{}{}:
				time.Sleep(rateLimiterSleep)
			case <-stop:
				return
			}
		}
	}()

	if fullFetch {
		return syncFull(db, db_config, apiKey, rateLimiter)
	}

	for {
		end := time.Now().UTC()
		hasLaterWindow := time.Since(since).Hours() > 24*120
		if hasLaterWindow {
			log.Println("lastModStartDate is older than 120 days compared to current date")
			end = since.AddDate(0, 0, 120)
		}

		if _, _, err := syncPages(db, apiURLTemplateFor(since, end), apiKey, rateLimiter); err != nil {
			return time.Time{}, err
		}
		if !hasLaterWindow {
			if err := pgsql.RetireStoredRejectedNvd(db); err != nil {
				return time.Time{}, err
			}
			if err := sourcesync.SetConfigLast(db_config, "nvd_last", end); err != nil {
				return time.Time{}, err
			}
			return end, nil
		}
		since = end
	}
}

// syncFull fetches every CVE, then retires stored records NVD no longer publishes.
func syncFull(db *bun.DB, db_config *bun.DB, apiKey string, rateLimiter chan struct{}) (time.Time, error) {
	started := time.Now().UTC()
	logger.WithFields(logrus.Fields{"source": knowledge.SourceNVD}).Info("No NVD watermark, performing a full fetch")

	total, snapshot, err := syncPages(db, fullURLTemplateFor, apiKey, rateLimiter)
	if err != nil {
		return time.Time{}, err
	}
	if len(snapshot) < total {
		return time.Time{}, fmt.Errorf("incomplete NVD fetch: %d of %d records", len(snapshot), total)
	}

	if err := pgsql.RetireStoredRejectedNvd(db); err != nil {
		return time.Time{}, err
	}
	if err := pgsql.ReconcileNvd(db, snapshot, started); err != nil {
		return time.Time{}, err
	}
	if err := sourcesync.SetConfigLast(db_config, "nvd_last", started); err != nil {
		return time.Time{}, err
	}
	return started, nil
}

// pageURL builds the request for one result page.
type pageURL func(elementPage, startIndex int) string

func apiURLTemplateFor(since, end time.Time) pageURL {
	sinceString := since.Format("2006-01-02T15:04:05.000Z")
	endString := end.Format("2006-01-02T15:04:05.000Z")
	return func(elementPage, startIndex int) string {
		return fmt.Sprintf(apiURLTemplate, elementPage, startIndex, sinceString, endString)
	}
}

func fullURLTemplateFor(elementPage, startIndex int) string {
	return fmt.Sprintf(fullURLTemplate, elementPage, startIndex)
}

// syncPages fetches and stores every page of one query and reports all page failures.
// It returns the upstream total and the distinct ids received.
func syncPages(db *bun.DB, urlFor pageURL, apiKey string, rateLimiter chan struct{}) (int, []string, error) {
	const elementPage = 2000

	var result NVDStats
	if err := fetchNVDStats(urlFor(elementPage, 0), apiKey, &result); err != nil {
		return 0, nil, fmt.Errorf("fetch NVD stats: %w", err)
	}
	log.Printf("Total CVEs: %d", result.TotalResults)

	nPage := result.TotalResults / elementPage
	if result.TotalResults%elementPage != 0 {
		nPage++
	}
	bar := progressbar.Default(int64(nPage))

	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []error
	seen := make(map[string]struct{}, result.TotalResults)
	for i := range nPage {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer bar.Add(1)

			ids, err := syncPage(db, urlFor(elementPage, i*elementPage), apiKey, rateLimiter)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				log.Printf("NVD page %d failed: %v", i, err)
				failures = append(failures, fmt.Errorf("page %d: %w", i, err))
				return
			}
			for _, id := range ids {
				seen[id] = struct{}{}
			}
		}(i)
	}
	wg.Wait()

	if err := errors.Join(failures...); err != nil {
		return 0, nil, err
	}
	snapshot := make([]string, 0, len(seen))
	for id := range seen {
		snapshot = append(snapshot, id)
	}
	return result.TotalResults, snapshot, nil
}

// syncPage stores one NVD page and its package links.
// It returns the id of every record on the page, including those not written.
func syncPage(db *bun.DB, pageRequest, apiKey string, rateLimiter chan struct{}) ([]string, error) {
	vulns, err := downloadBatch(pageRequest, apiKey, rateLimiter)
	if err != nil {
		return nil, err
	}

	if err := pgsql.UpdateNvd(db, vulns); err != nil {
		return nil, err
	}

	nvdIds := make([]string, len(vulns))
	for j, v := range vulns {
		nvdIds[j] = v.NVDId
	}
	nvdIdToUUID, err := pgsql.GetNvdUUIDsByNvdIds(db, nvdIds)
	if err != nil {
		return nil, fmt.Errorf("get NVD UUIDs: %w", err)
	}

	writtenUUIDs := make([]uuid.UUID, 0, len(vulns))
	for _, v := range vulns {
		if id, ok := nvdIdToUUID[v.NVDId]; ok && nvdRecordKeepsLinks(v) {
			writtenUUIDs = append(writtenUUIDs, id)
		}
	}
	pkgVulns := extractPackageVulnerabilitiesFromNVD(vulns, nvdIdToUUID)
	if err := pgsql.ReplaceNvdPackageLinks(db, writtenUUIDs, pkgVulns); err != nil {
		return nil, fmt.Errorf("replace package links: %w", err)
	}
	return nvdIds, nil
}

// nvdRecordKeepsLinks reports whether a record's package links follow this page.
// Rejected records are retired and deferred records are not written.
func nvdRecordKeepsLinks(item knowledge.NVDItem) bool {
	return item.VulnStatus != "Rejected" && item.VulnStatus != "Deferred"
}

func fetchNVDStats(url, apiKey string, result *NVDStats) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	if apiKey != "" {
		req.Header.Add("apiKey", apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("error executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %w", err)
	}

	err = json.Unmarshal(body, result)
	if err != nil {
		return fmt.Errorf("error unmarshalling response body: %w", err)
	}

	return nil
}

// extractPackageVulnerabilitiesFromNVD extracts package-vulnerability relationships from NVD items.
// Uses the nvdIdToUUID map to set the FK reference to the NVD table.
// Note: NVD uses CPE which doesn't map directly to npm/packagist packages.
func extractPackageVulnerabilitiesFromNVD(nvdItems []knowledge.NVDItem, nvdIdToUUID map[string]uuid.UUID) []knowledge.PackageVulnerability {
	var pkgVulns []knowledge.PackageVulnerability
	seen := make(map[string]bool) // Deduplicate within batch

	for _, nvd := range nvdItems {
		if !nvdRecordKeepsLinks(nvd) {
			continue
		}

		// Look up the UUID for this NVD record
		nvdUUID, ok := nvdIdToUUID[nvd.NVDId]
		if !ok {
			continue
		}

		for _, source := range nvd.AffectedFlattened {
			if source.CriteriaDict.Product == "" || source.CriteriaDict.Product == "*" {
				continue
			}

			// Create a unique key for deduplication
			key := fmt.Sprintf("%s:%s", source.CriteriaDict.Product, nvd.NVDId)
			if seen[key] {
				continue
			}
			seen[key] = true

			pkgVuln := knowledge.PackageVulnerability{
				PackageName:      source.CriteriaDict.Product,
				PackageEcosystem: "nvd", // NVD uses CPE, doesn't map directly to npm/packagist
				NvdId:            &nvdUUID,
			}
			pkgVulns = append(pkgVulns, pkgVuln)
		}
	}

	return pkgVulns
}

func downloadBatch(url, apiKey string, rateLimiter chan struct{}) ([]knowledge.NVDItem, error) {
	var resp *http.Response
	var err error
	var retries int
	maxRetries := 5

	for retries = 0; retries < maxRetries; retries++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("error creating request: %w", err)
		}

		if apiKey != "" {
			req.Header.Add("apiKey", apiKey)
		}

		<-rateLimiter // Wait for rate limiter token
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("error executing request: %v, retrying... (%d/%d)", err, retries+1, maxRetries)
			time.Sleep(time.Duration(2<<retries) * time.Second) // Exponential backoff
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			log.Printf("rate limit exceeded, retrying... (%d/%d)", retries+1, maxRetries)
			time.Sleep(time.Duration(2<<retries) * time.Second) // Exponential backoff
			continue
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
		}

		break
	}

	if retries == maxRetries {
		return nil, fmt.Errorf("max retries reached, unable to fetch data")
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	var result knowledge.NVD
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling response body: %w", err)
	}

	return knowledge.GetVulns(result), nil
}
