// Package gcve provides functionality to synchronize vulnerability data
// from CIRCL's vulnerability-lookup service (GCVE/CVE data).
// Uses NDJSON bulk dumps for initial load and incremental API for updates.
package gcve

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/uptrace/bun"
)

var logger = logrus.StandardLogger()

// Upstream endpoints, replaceable in tests.
var (
	bulkDumpURL      = "https://vulnerability.circl.lu/dumps/cvelistv5.ndjson"
	vulnrichmentURL  = "https://vulnerability.circl.lu/dumps/vulnrichment.ndjson"
	vulnerabilityAPI = "https://vulnerability.circl.lu/api/vulnerability/"
)

// stateRejected is the CVE record state of a rejected record.
const stateRejected = "REJECTED"

// windowRequestInterval keeps requests under the anonymous limit of 20 a minute.
var windowRequestInterval = 3 * time.Second

const (
	batchSize = 100
	// windowPageSize is the largest page the API serves.
	windowPageSize = 100
	// windowOverlap re-reads recent records, because upstream can publish a change late.
	windowOverlap = 24 * time.Hour
	// maxWindowRequests stops a misbehaving API from keeping the run going forever.
	maxWindowRequests = 5000
	maxWindowRetries  = 5
	userAgent         = "CodeClarity-knowledge (+https://github.com/CodeClarityCE)"
)

// httpClient is a shared HTTP client with timeouts for all GCVE requests.
// Bulk downloads are ~4.7GB so the timeout must be generous.
var httpClient = &http.Client{
	Timeout: 30 * time.Minute,
}

// Update synchronizes GCVE/CVE data from vulnerability-lookup.
// Uses bulk dump for initial load, incremental API for subsequent updates.
func Update(db *bun.DB, db_config *bun.DB) error {
	return sourcesync.RunCounted(db, knowledge.SourceGCVE, func() (sourcesync.Result, error) {
		return sync(db, db_config)
	})
}

// sync returns the time the data is complete up to, taken before any fetch, and the upstream
// total when the run read the whole dump.
func sync(db *bun.DB, db_config *bun.DB) (sourcesync.Result, error) {
	log.Println("Start updating GCVE/vulnerability-lookup")

	bulkTime, err := sourcesync.BulkCompletedAt(db, knowledge.SourceGCVE)
	if err != nil {
		return sourcesync.Result{}, err
	}
	last, err := sourcesync.Watermark(db, knowledge.SourceGCVE)
	if err != nil {
		return sourcesync.Result{}, err
	}
	syncedAt := time.Now()
	var total *int64

	switch {
	case !bulkTime.IsZero():
		logger.WithFields(logrus.Fields{"source": knowledge.SourceGCVE, "bulk_completed_at": bulkTime.UTC().Format(time.RFC3339)}).Info("GCVE bulk import already done, retrying enrichment and reconcile")
		total, err = retryAfterBulk(db, bulkTime, syncedAt)
	case last.IsZero():
		log.Println("No previous GCVE sync, performing full bulk import")
		total, err = fullImport(db, syncedAt)
	case time.Since(last).Hours() > 24*30:
		log.Println("GCVE data older than 30 days, performing full reimport")
		total, err = fullImport(db, syncedAt)
	default:
		syncedAt, total, err = incrementalOrBulk(db, last, syncedAt)
	}
	if err != nil {
		return sourcesync.Result{}, err
	}

	if err := pgsql.RetireStoredRejectedGcve(db); err != nil {
		return sourcesync.Result{}, err
	}

	if err := sourcesync.SetConfigLast(db_config, "gcve_last", syncedAt); err != nil {
		return sourcesync.Result{}, err
	}
	return sourcesync.Result{Watermark: syncedAt, UpstreamTotal: total}, nil
}

// distinctTotal counts the distinct record ids upstream offered, since the dump and its enrichment overlap.
func distinctTotal(ids []string) *int64 {
	distinct := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		distinct[id] = struct{}{}
	}
	return sourcesync.Total(len(distinct))
}

// fullImport loads the dump, enriches it, catches up from the dump's date and reconciles.
// It records the bulk import as done first, so a later run only has to retry the enrichment.
func fullImport(db *bun.DB, syncedAt time.Time) (*int64, error) {
	dumpTime, ids, err := bulkImport(db, time.Time{})
	if err != nil {
		return nil, fmt.Errorf("bulk import: %w", err)
	}
	if err := sourcesync.SetBulkCompletedAt(db, knowledge.SourceGCVE, dumpTime); err != nil {
		return nil, err
	}
	enriched, err := importVulnrichment(db)
	if err != nil {
		return nil, fmt.Errorf("vulnrichment import: %w", err)
	}
	caughtUp, err := catchUp(db, dumpTime)
	if err != nil {
		return nil, err
	}

	snapshot := make([]string, 0, len(ids)+len(enriched)+len(caughtUp))
	snapshot = append(append(append(snapshot, ids...), enriched...), caughtUp...)
	return distinctTotal(snapshot), pgsql.ReconcileGcve(db, snapshot, syncedAt)
}

// retryAfterBulk finishes a full import whose enrichment failed, enriching first because that is what failed.
// It reads the dump again without storing it, to get the ids the reconcile needs.
func retryAfterBulk(db *bun.DB, dumpTime, syncedAt time.Time) (*int64, error) {
	enriched, err := importVulnrichment(db)
	if err != nil {
		return nil, fmt.Errorf("vulnrichment import: %w", err)
	}
	caughtUp, err := catchUp(db, dumpTime)
	if err != nil {
		return nil, err
	}
	dumped, err := dumpRecordIDs(dumpTime)
	if err != nil {
		return nil, fmt.Errorf("read dump for reconcile: %w", err)
	}

	snapshot := make([]string, 0, len(dumped)+len(enriched)+len(caughtUp))
	snapshot = append(append(append(snapshot, dumped...), enriched...), caughtUp...)
	return distinctTotal(snapshot), pgsql.ReconcileGcve(db, snapshot, syncedAt)
}

// catchUp applies the changes made since the dump was built.
func catchUp(db *bun.DB, dumpTime time.Time) ([]string, error) {
	records, err := fetchWindow(dumpTime.Add(-windowOverlap))
	if err != nil {
		return nil, fmt.Errorf("catch up from dump: %w", err)
	}
	if err := storeRecentRecords(db, records); err != nil {
		return nil, err
	}
	return recordGcveIds(records), nil
}

// recordGcveIds returns the ids of the records that parse.
func recordGcveIds(records []json.RawMessage) []string {
	ids := make([]string, 0, len(records))
	for _, record := range records {
		if item, err := parseCVERecord(record); err == nil {
			ids = append(ids, item.GCVEId)
		}
	}
	return ids
}

// incrementalOrBulk reads the window since the last sync, overlapping it a little.
// It returns the watermark: the run's start, or the dump's date after a fallback.
// Only the fallback reads all of upstream, so only it returns a total.
// A bad record or failed batch fails the source without a bulk download.
func incrementalOrBulk(db *bun.DB, last, syncedAt time.Time) (time.Time, *int64, error) {
	records, fetchErr := fetchWindow(last.Add(-windowOverlap))
	if fetchErr == nil {
		return syncedAt, nil, storeRecentRecords(db, records)
	}
	log.Printf("GCVE incremental fetch failed, falling back to bulk import: %v", fetchErr)
	dumpTime, ids, err := bulkImport(db, last)
	if err != nil {
		return time.Time{}, nil, errors.Join(fmt.Errorf("incremental fetch: %w", fetchErr), fmt.Errorf("fallback bulk import: %w", err))
	}
	return dumpTime, distinctTotal(ids), nil
}

// bulkImport downloads and stores the cvelistv5 dump, refusing one older than notBefore.
// It returns the dump's date and the ids of all its records.
func bulkImport(db *bun.DB, notBefore time.Time) (time.Time, []string, error) {
	logger.Info("Downloading cvelistv5 bulk dump")
	body, dumpTime, err := openDump(notBefore)
	if err != nil {
		return time.Time{}, nil, err
	}
	defer body.Close()

	ids, err := processNDJSONStream(db, body)
	if err != nil {
		return time.Time{}, nil, err
	}
	if len(ids) == 0 {
		return time.Time{}, nil, fmt.Errorf("cvelistv5 dump: %w", sourcesync.ErrNoUpstreamRecords)
	}
	return dumpTime, ids, nil
}

// openDump requests the cvelistv5 dump and checks its date is not older than notBefore.
func openDump(notBefore time.Time) (io.ReadCloser, time.Time, error) {
	resp, err := httpClient.Get(bulkDumpURL)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to download bulk dump: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, time.Time{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	dumpTime, err := http.ParseTime(resp.Header.Get("Last-Modified"))
	if err != nil {
		resp.Body.Close()
		return nil, time.Time{}, fmt.Errorf("bulk dump has no usable Last-Modified: %w", err)
	}
	if dumpTime.Before(notBefore) {
		resp.Body.Close()
		return nil, time.Time{}, fmt.Errorf("bulk dump from %s is older than the watermark %s", dumpTime.Format(time.RFC3339), notBefore.Format(time.RFC3339))
	}
	return resp.Body, dumpTime, nil
}

// dumpRecordIDs reads the id of every dump record without storing anything.
func dumpRecordIDs(notBefore time.Time) ([]string, error) {
	logger.Info("Reading cvelistv5 bulk dump for its record ids")
	body, _, err := openDump(notBefore)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	scanner := newRecordScanner(body)
	var ids []string
	parseErrors := 0
	for scanner.Scan() {
		if len(scanner.Bytes()) == 0 {
			continue
		}
		item, err := parseCVERecord(scanner.Bytes())
		if err != nil {
			parseErrors++
			continue
		}
		ids = append(ids, item.GCVEId)
	}
	if parseErrors > 0 {
		return nil, fmt.Errorf("%d records could not be parsed", parseErrors)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("cvelistv5 dump: %w", sourcesync.ErrNoUpstreamRecords)
	}
	return ids, nil
}

// newRecordScanner reads NDJSON lines up to the longest record the dumps contain.
func newRecordScanner(reader io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024) // 10MB max line
	return scanner
}

// importVulnrichment downloads and merges CISA ADP enrichment data.
func importVulnrichment(db *bun.DB) ([]string, error) {
	log.Println("Downloading vulnrichment dump...")

	resp, err := httpClient.Get(vulnrichmentURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download vulnrichment dump: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	ids, err := processNDJSONStream(db, resp.Body)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("vulnrichment dump: %w", sourcesync.ErrNoUpstreamRecords)
	}
	return ids, nil
}

// processNDJSONStream reads an NDJSON stream line by line and processes in batches.
// It returns the id of every record read, including rejected ones.
func processNDJSONStream(db *bun.DB, reader io.Reader) ([]string, error) {
	scanner := newRecordScanner(reader)

	var batch []knowledge.GCVEItem
	var failures []error
	var ids []string
	totalProcessed := 0
	parseErrors := 0
	rejected := 0

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		item, err := parseCVERecord(line)
		if err != nil {
			parseErrors++
			continue
		}
		if item.State == stateRejected {
			rejected++
		}
		ids = append(ids, item.GCVEId)

		batch = append(batch, *item)

		if len(batch) >= batchSize {
			if err := processBatch(db, batch); err != nil {
				log.Printf("Error processing GCVE batch: %v", err)
				failures = append(failures, err)
			}
			totalProcessed += len(batch)
			batch = batch[:0]

			if totalProcessed%10000 == 0 {
				log.Printf("GCVE: processed %d records", totalProcessed)
			}
		}
	}

	// Process remaining
	if len(batch) > 0 {
		if err := processBatch(db, batch); err != nil {
			log.Printf("Error processing final GCVE batch: %v", err)
			failures = append(failures, err)
		}
		totalProcessed += len(batch)
	}

	log.Printf("GCVE: total %d CVE records processed, %d parse errors, %d rejected", totalProcessed, parseErrors, rejected)
	if parseErrors > 0 {
		failures = append(failures, fmt.Errorf("%d records could not be parsed", parseErrors))
	}
	failures = append(failures, scanner.Err())
	return ids, errors.Join(failures...)
}

// CVERecordRaw represents the raw JSON structure from the NDJSON dump.
type CVERecordRaw struct {
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
	CveMetadata struct {
		CveId             string `json:"cveId"`
		AssignerOrgId     string `json:"assignerOrgId"`
		AssignerShortName string `json:"assignerShortName"`
		State             string `json:"state"`
		DateReserved      string `json:"dateReserved"`
		DatePublished     string `json:"datePublished"`
		DateUpdated       string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA json.RawMessage   `json:"cna"`
		ADP []json.RawMessage `json:"adp"`
	} `json:"containers"`
}

type CNAContainer struct {
	Affected     []json.RawMessage           `json:"affected"`
	Descriptions []knowledge.GCVEDescription `json:"descriptions"`
	Metrics      []json.RawMessage           `json:"metrics"`
	ProblemTypes []knowledge.GCVEProblemType `json:"problemTypes"`
	References   []knowledge.GCVEReference   `json:"references"`
}

type RawAffected struct {
	Vendor        string                  `json:"vendor"`
	Product       string                  `json:"product"`
	DefaultStatus string                  `json:"defaultStatus,omitempty"`
	Versions      []knowledge.GCVEVersion `json:"versions"`
	Platforms     []string                `json:"platforms,omitempty"`
}

type ADPContainer struct {
	ProviderMetadata struct {
		OrgId     string `json:"orgId"`
		ShortName string `json:"shortName"`
	} `json:"providerMetadata"`
	Title    string            `json:"title,omitempty"`
	Affected []RawAffected     `json:"affected,omitempty"`
	Metrics  []json.RawMessage `json:"metrics,omitempty"`
}

// cveToGCVEId converts a CVE ID (e.g., "CVE-2024-1234") to GCVE format
// (e.g., "GCVE-0-2024-1234") using GNA ID 0 for legacy CVE identifiers.
func cveToGCVEId(cveId string) string {
	if strings.HasPrefix(cveId, "CVE-") {
		return "GCVE-0-" + cveId[4:]
	}
	return cveId
}

// parseCVERecord transforms the raw CVE Record v5.x JSON into a GCVEItem.
func parseCVERecord(data []byte) (*knowledge.GCVEItem, error) {
	var raw CVERecordRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	if raw.CveMetadata.CveId == "" {
		return nil, errors.New("record has no CVE id")
	}

	item := &knowledge.GCVEItem{
		GCVEId:        cveToGCVEId(raw.CveMetadata.CveId),
		CVEId:         raw.CveMetadata.CveId,
		DataVersion:   raw.DataVersion,
		State:         raw.CveMetadata.State,
		DatePublished: raw.CveMetadata.DatePublished,
		DateUpdated:   raw.CveMetadata.DateUpdated,
		AssignerOrgId: raw.CveMetadata.AssignerOrgId,
	}

	// Only the identity and dates of a rejected record are used.
	if item.State == stateRejected {
		fillEmptyFields(item)
		return item, nil
	}

	// Parse CNA container
	if len(raw.Containers.CNA) > 0 {
		var cna CNAContainer
		if err := json.Unmarshal(raw.Containers.CNA, &cna); err == nil {
			item.Descriptions = cna.Descriptions
			item.References = cna.References
			item.ProblemTypes = cna.ProblemTypes

			// Parse affected products
			for _, rawAff := range cna.Affected {
				var aff RawAffected
				if err := json.Unmarshal(rawAff, &aff); err == nil {
					item.Affected = append(item.Affected, knowledge.GCVEAffected{
						Vendor:        aff.Vendor,
						Product:       aff.Product,
						DefaultStatus: aff.DefaultStatus,
						Versions:      aff.Versions,
						Platforms:     aff.Platforms,
					})
				}
			}

			// Parse metrics
			item.Metrics = parseMetrics(cna.Metrics)

			// Extract CWE IDs from problem types
			item.Cwes = extractCWEIds(cna.ProblemTypes)
		}
	}

	// Parse ADP enrichments
	for _, rawAdp := range raw.Containers.ADP {
		var adp ADPContainer
		if err := json.Unmarshal(rawAdp, &adp); err == nil {
			gcveAdp := knowledge.GCVEAdp{
				ProviderOrgId: adp.ProviderMetadata.OrgId,
				ShortName:     adp.ProviderMetadata.ShortName,
				Title:         adp.Title,
				Metrics:       parseMetrics(adp.Metrics),
			}

			// Parse ADP affected (may contain additional CPE data)
			for _, aff := range adp.Affected {
				gcveAdp.Affected = append(gcveAdp.Affected, knowledge.GCVEAffected{
					Vendor:        aff.Vendor,
					Product:       aff.Product,
					DefaultStatus: aff.DefaultStatus,
					Versions:      aff.Versions,
					Platforms:     aff.Platforms,
				})
			}

			item.ADPEnrichments = append(item.ADPEnrichments, gcveAdp)
		}
	}

	// Build affected_flattened from both CNA and ADP affected products,
	// deduplicated by vendor+product pair.
	var allAffected []knowledge.GCVEAffected
	allAffected = append(allAffected, item.Affected...)
	for _, adp := range item.ADPEnrichments {
		allAffected = append(allAffected, adp.Affected...)
	}
	item.AffectedFlattened = buildAffectedFlattened(allAffected)

	fillEmptyFields(item)
	return item, nil
}

// fillEmptyFields stores empty lists instead of nil for JSONB storage.
func fillEmptyFields(item *knowledge.GCVEItem) {
	if item.Descriptions == nil {
		item.Descriptions = []knowledge.GCVEDescription{}
	}
	if item.Affected == nil {
		item.Affected = []knowledge.GCVEAffected{}
	}
	if item.AffectedFlattened == nil {
		item.AffectedFlattened = []knowledge.GCVEProduct{}
	}
	if item.Metrics == nil {
		item.Metrics = []knowledge.GCVEMetricEntry{}
	}
	if item.ProblemTypes == nil {
		item.ProblemTypes = []knowledge.GCVEProblemType{}
	}
	if item.References == nil {
		item.References = []knowledge.GCVEReference{}
	}
	if item.ADPEnrichments == nil {
		item.ADPEnrichments = []knowledge.GCVEAdp{}
	}
	if item.Cwes == nil {
		item.Cwes = []string{}
	}
}

// parseMetrics parses raw metric JSON entries into typed GCVEMetricEntry structs.
func parseMetrics(rawMetrics []json.RawMessage) []knowledge.GCVEMetricEntry {
	var result []knowledge.GCVEMetricEntry

	for _, raw := range rawMetrics {
		var entry knowledge.GCVEMetricEntry
		if err := json.Unmarshal(raw, &entry); err == nil {
			result = append(result, entry)
		}
	}

	return result
}

// extractCWEIds extracts unique CWE IDs from problem types.
func extractCWEIds(problemTypes []knowledge.GCVEProblemType) []string {
	seen := make(map[string]bool)
	var cwes []string

	for _, pt := range problemTypes {
		for _, desc := range pt.Descriptions {
			if desc.CweId != "" && !seen[desc.CweId] {
				seen[desc.CweId] = true
				cwes = append(cwes, desc.CweId)
			}
		}
	}

	return cwes
}

// buildAffectedFlattened creates the denormalized vendor+product list for GIN index queries.
func buildAffectedFlattened(affected []knowledge.GCVEAffected) []knowledge.GCVEProduct {
	seen := make(map[string]bool)
	var products []knowledge.GCVEProduct

	for _, aff := range affected {
		if aff.Product == "" {
			continue
		}
		key := strings.ToLower(aff.Vendor) + "|" + strings.ToLower(aff.Product)
		if !seen[key] {
			seen[key] = true
			products = append(products, knowledge.GCVEProduct{
				Vendor:  strings.ToLower(aff.Vendor),
				Product: strings.ToLower(aff.Product),
			})
		}
	}

	return products
}

// processBatch inserts GCVE records and creates package-vulnerability links.
func processBatch(db *bun.DB, items []knowledge.GCVEItem) error {
	batch := make([]knowledge.GCVEItem, 0, len(items))
	var rejected []knowledge.GCVEItem
	for _, item := range items {
		if item.State == stateRejected {
			rejected = append(rejected, item)
		} else {
			batch = append(batch, item)
		}
	}
	if err := pgsql.StoreRejectedGcve(db, rejected); err != nil {
		return err
	}

	// Step 1: Upsert GCVE records
	if err := pgsql.BatchUpdateGcve(db, batch); err != nil {
		return fmt.Errorf("batch update failed: %w", err)
	}

	// Step 2: Get UUIDs for inserted records
	gcveIds := make([]string, len(batch))
	for i, item := range batch {
		gcveIds[i] = item.GCVEId
	}

	gcveIdToUUID, err := pgsql.GetGcveUUIDsByGcveIds(db, gcveIds)
	if err != nil {
		return fmt.Errorf("failed to get GCVE UUIDs: %w", err)
	}

	// Step 3: Extract and insert package-vulnerability relationships
	advisoryUUIDs := make([]uuid.UUID, 0, len(gcveIdToUUID))
	for _, id := range gcveIdToUUID {
		advisoryUUIDs = append(advisoryUUIDs, id)
	}
	pkgVulns := extractPackageVulnerabilities(batch, gcveIdToUUID)
	if err := pgsql.ReplaceGcvePackageLinks(db, advisoryUUIDs, pkgVulns); err != nil {
		return fmt.Errorf("replace package links: %w", err)
	}

	return nil
}

// extractPackageVulnerabilities creates package-vulnerability junction records from GCVE items.
func extractPackageVulnerabilities(gcveItems []knowledge.GCVEItem, gcveIdToUUID map[string]uuid.UUID) []knowledge.PackageVulnerability {
	var pkgVulns []knowledge.PackageVulnerability
	seen := make(map[string]bool)

	for _, item := range gcveItems {
		gcveUUID, ok := gcveIdToUUID[item.GCVEId]
		if !ok {
			continue
		}

		for _, aff := range item.Affected {
			if aff.Product == "" || aff.Product == "*" {
				continue
			}

			key := fmt.Sprintf("%s|gcve|%s", strings.ToLower(aff.Product), item.GCVEId)
			if seen[key] {
				continue
			}
			seen[key] = true

			pkgVuln := knowledge.PackageVulnerability{
				PackageName:      strings.ToLower(aff.Product),
				PackageEcosystem: "gcve",
				GcveId:           &gcveUUID,
			}
			pkgVulns = append(pkgVulns, pkgVuln)
		}

		// Also index ADP affected products
		for _, adp := range item.ADPEnrichments {
			for _, aff := range adp.Affected {
				if aff.Product == "" || aff.Product == "*" {
					continue
				}

				key := fmt.Sprintf("%s|gcve|%s", strings.ToLower(aff.Product), item.GCVEId)
				if seen[key] {
					continue
				}
				seen[key] = true

				pkgVuln := knowledge.PackageVulnerability{
					PackageName:      strings.ToLower(aff.Product),
					PackageEcosystem: "gcve",
					GcveId:           &gcveUUID,
				}
				pkgVulns = append(pkgVulns, pkgVuln)
			}
		}
	}

	return pkgVulns
}

// fetchWindow reads every cvelistv5 record updated since the given time, moving its
// cursor by date so updates made during the run cannot hide an unread record.
func fetchWindow(since time.Time) ([]json.RawMessage, error) {
	log.Printf("GCVE incremental update since %s", since.Format(time.RFC3339))

	seen := make(map[string]struct{})
	var records []json.RawMessage
	cursor := since.UTC()
	page := 1
	for requests := 0; requests < maxWindowRequests; requests++ {
		body, err := fetchWindowPage(cursor, page)
		if err != nil {
			return nil, err
		}
		var pageRecords []json.RawMessage
		if err := json.Unmarshal(body, &pageRecords); err != nil {
			return nil, fmt.Errorf("failed to parse response: %w", err)
		}

		fresh := 0
		next := cursor
		for i, record := range pageRecords {
			var meta struct {
				CveMetadata struct {
					CveId       string `json:"cveId"`
					DateUpdated string `json:"dateUpdated"`
				} `json:"cveMetadata"`
			}
			if err := json.Unmarshal(record, &meta); err != nil || meta.CveMetadata.CveId == "" {
				records = append(records, record)
				continue
			}
			id := meta.CveMetadata.CveId
			if _, known := seen[id]; !known {
				seen[id] = struct{}{}
				records = append(records, record)
				fresh++
			}
			updated, err := time.Parse(time.RFC3339Nano, meta.CveMetadata.DateUpdated)
			if err != nil {
				continue
			}
			if i == 0 && updated.Before(cursor) {
				return nil, fmt.Errorf("upstream ignored the window: record %s is dated %s, before %s", id, meta.CveMetadata.DateUpdated, cursor.Format(time.RFC3339))
			}
			if updated.After(next) {
				next = updated
			}
		}

		if fresh == 0 && len(pageRecords) < windowPageSize {
			return records, nil
		}
		if next.After(cursor) {
			cursor = next
			page = 1
		} else {
			page++
		}
		time.Sleep(windowRequestInterval)
	}
	return nil, fmt.Errorf("window not finished after %d requests", maxWindowRequests)
}

// fetchWindowPage requests one page in ascending update order, waiting out rate limits.
func fetchWindowPage(since time.Time, page int) ([]byte, error) {
	query := url.Values{}
	query.Set("source", "cvelistv5")
	query.Set("since", since.Format("2006-01-02T15:04:05.000Z"))
	query.Set("date_sort", "updated")
	query.Set("sort_order", "asc")
	query.Set("per_page", strconv.Itoa(windowPageSize))
	query.Set("page", strconv.Itoa(page))

	apiKey := os.Getenv("VULNERABILITY_LOOKUP_API_KEY")
	for attempt := 0; attempt < maxWindowRetries; attempt++ {
		req, err := http.NewRequest("GET", vulnerabilityAPI+"?"+query.Encode(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		if apiKey != "" && apiKey != "!ChangeMe!" {
			req.Header.Set("X-API-KEY", apiKey)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch window: %w", err)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			delay, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
			resp.Body.Close()
			time.Sleep(time.Duration(delay) * time.Second)
			continue
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}
		if readErr != nil {
			return nil, fmt.Errorf("failed to read response body: %w", readErr)
		}
		return body, nil
	}
	return nil, fmt.Errorf("rate limited after %d attempts", maxWindowRetries)
}

// storeRecentRecords stores the fetched records and reports every record and batch failure.
func storeRecentRecords(db *bun.DB, records []json.RawMessage) error {
	var batch []knowledge.GCVEItem
	var failures []error
	processed := 0
	parseErrors := 0

	for _, record := range records {
		item, err := parseCVERecord(record)
		if err != nil {
			parseErrors++
			continue
		}
		batch = append(batch, *item)

		if len(batch) >= batchSize {
			if err := processBatch(db, batch); err != nil {
				log.Printf("Error processing incremental GCVE batch: %v", err)
				failures = append(failures, err)
			}
			processed += len(batch)
			batch = batch[:0]
		}
	}

	if len(batch) > 0 {
		if err := processBatch(db, batch); err != nil {
			log.Printf("Error processing final incremental GCVE batch: %v", err)
			failures = append(failures, err)
		}
		processed += len(batch)
	}

	log.Printf("GCVE incremental update: %d records processed", processed)
	if parseErrors > 0 {
		failures = append(failures, fmt.Errorf("%d records could not be parsed", parseErrors))
	}
	return errors.Join(failures...)
}

// UseUpstream points the mirror at other dump, enrichment and update window URLs, without
// pausing between window requests, and returns a function that undoes it.
func UseUpstream(bulk, enrichment, window string) (restore func()) {
	original := []string{bulkDumpURL, vulnrichmentURL, vulnerabilityAPI}
	originalInterval := windowRequestInterval
	bulkDumpURL, vulnrichmentURL, vulnerabilityAPI, windowRequestInterval = bulk, enrichment, window, 0
	return func() {
		bulkDumpURL, vulnrichmentURL, vulnerabilityAPI = original[0], original[1], original[2]
		windowRequestInterval = originalInterval
	}
}
