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
	"github.com/uptrace/bun"
)

// apiURLTemplate is the NVD CVE API, with page size, start index and modified-date window.
var apiURLTemplate = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=%d&startIndex=%d&lastModStartDate=%s&lastModEndDate=%s"

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

	for {
		end := time.Now().UTC()
		hasLaterWindow := time.Since(since).Hours() > 24*120
		if hasLaterWindow {
			log.Println("lastModStartDate is older than 120 days compared to current date")
			end = since.AddDate(0, 0, 120)
		}

		if err := syncWindow(db, since, end, apiKey, rateLimiter); err != nil {
			return time.Time{}, err
		}
		if !hasLaterWindow {
			if err := sourcesync.SetConfigLast(db_config, "nvd_last", end); err != nil {
				return time.Time{}, err
			}
			return end, nil
		}
		since = end
	}
}

// syncWindow fetches and stores every page of one modified-date window and reports all page failures.
func syncWindow(db *bun.DB, since, end time.Time, apiKey string, rateLimiter chan struct{}) error {
	const elementPage = 2000
	sinceString := since.Format("2006-01-02T15:04:05.000Z")
	endString := end.Format("2006-01-02T15:04:05.000Z")

	var result NVDStats
	if err := fetchNVDStats(apiURLTemplate, elementPage, sinceString, endString, apiKey, &result); err != nil {
		return fmt.Errorf("fetch NVD stats: %w", err)
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
	for i := range nPage {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer bar.Add(1)

			if err := syncPage(db, i, elementPage, sinceString, endString, apiKey, rateLimiter); err != nil {
				log.Printf("NVD page %d failed: %v", i, err)
				mu.Lock()
				failures = append(failures, fmt.Errorf("page %d: %w", i, err))
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	return errors.Join(failures...)
}

// syncPage stores one NVD page and its package links.
func syncPage(db *bun.DB, i, elementPage int, since, end, apiKey string, rateLimiter chan struct{}) error {
	vulns, err := downloadBatch(i, elementPage, apiURLTemplate, since, end, apiKey, rateLimiter)
	if err != nil {
		return err
	}

	if err := pgsql.UpdateNvd(db, vulns); err != nil {
		return err
	}

	nvdIds := make([]string, len(vulns))
	for j, v := range vulns {
		nvdIds[j] = v.NVDId
	}
	nvdIdToUUID, err := pgsql.GetNvdUUIDsByNvdIds(db, nvdIds)
	if err != nil {
		return fmt.Errorf("get NVD UUIDs: %w", err)
	}

	pkgVulns := extractPackageVulnerabilitiesFromNVD(vulns, nvdIdToUUID)
	if err := pgsql.BatchInsertNvdPackageVulnerabilities(db, pkgVulns); err != nil {
		return fmt.Errorf("insert package links: %w", err)
	}
	return nil
}

func fetchNVDStats(urlTemplate string, element_page int, since, now_string, apiKey string, result *NVDStats) error {
	url := fmt.Sprintf(urlTemplate, element_page, 0, since, now_string)
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

func downloadBatch(i, element_page int, urlTemplate, since, now_string, apiKey string, rateLimiter chan struct{}) ([]knowledge.NVDItem, error) {
	index := i * element_page
	url := fmt.Sprintf(urlTemplate, element_page, index, since, now_string)

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
