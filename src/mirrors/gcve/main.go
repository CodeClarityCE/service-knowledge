// Package gcve provides functionality to synchronize vulnerability data
// from CIRCL's vulnerability-lookup service (GCVE/CVE data).
// Uses NDJSON bulk dumps for initial load and incremental API for updates.
package gcve

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	config "github.com/CodeClarityCE/utility-types/config_db"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

const (
	bulkDumpURL     = "https://vulnerability.circl.lu/dumps/cvelistv5.ndjson"
	vulnrichmentURL = "https://vulnerability.circl.lu/dumps/vulnrichment.ndjson"
	lastUpdatedAPI  = "https://vulnerability.circl.lu/api/last"
	batchSize       = 100
)

// Update synchronizes GCVE/CVE data from vulnerability-lookup.
// Uses bulk dump for initial load, incremental API for subsequent updates.
func Update(db *bun.DB, db_config *bun.DB) error {
	log.Println("Start updating GCVE/vulnerability-lookup")

	conf, err := getLastGCVESync(db_config)
	if err != nil {
		log.Println("Can't get config for GCVE sync", err)
		return err
	}

	if conf.GcveLast.IsZero() {
		log.Println("No previous GCVE sync, performing full bulk import")
		if err := bulkImport(db); err != nil {
			log.Printf("GCVE bulk import failed: %v", err)
			return err
		}
		if err := importVulnrichment(db); err != nil {
			log.Printf("Vulnrichment import failed (non-fatal): %v", err)
		}
		conf.GcveLast = time.Now()
		return setLastGCVESync(db_config, conf)
	}

	// If data is too old, do full reimport
	if time.Since(conf.GcveLast).Hours() > 24*30 {
		log.Println("GCVE data older than 30 days, performing full reimport")
		if err := bulkImport(db); err != nil {
			log.Printf("GCVE bulk reimport failed: %v", err)
			return err
		}
		if err := importVulnrichment(db); err != nil {
			log.Printf("Vulnrichment reimport failed (non-fatal): %v", err)
		}
		conf.GcveLast = time.Now()
		return setLastGCVESync(db_config, conf)
	}

	// Incremental update via API
	if err := incrementalUpdate(db, conf.GcveLast); err != nil {
		log.Printf("GCVE incremental update failed, falling back to bulk import: %v", err)
		if err := bulkImport(db); err != nil {
			return fmt.Errorf("GCVE fallback bulk import failed: %w", err)
		}
	}

	conf.GcveLast = time.Now()
	return setLastGCVESync(db_config, conf)
}

func getLastGCVESync(db_config *bun.DB) (config.Config, error) {
	ctx := context.Background()
	var configs []config.Config
	err := db_config.NewSelect().Model(&configs).Limit(1).Scan(ctx)
	if err != nil {
		return config.Config{}, err
	}
	if len(configs) == 0 {
		return config.Config{}, fmt.Errorf("no config found")
	}
	return configs[0], nil
}

func setLastGCVESync(db_config *bun.DB, conf config.Config) error {
	_, err := db_config.NewUpdate().Model(&conf).Where("id = ?", conf.Id).Exec(context.Background())
	if err != nil {
		log.Println("Failed to update GCVE sync timestamp:", err)
		return err
	}
	return nil
}

// bulkImport downloads and processes the cvelistv5 NDJSON dump.
func bulkImport(db *bun.DB) error {
	log.Println("Downloading cvelistv5 bulk dump...")

	resp, err := http.Get(bulkDumpURL)
	if err != nil {
		return fmt.Errorf("failed to download bulk dump: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return processNDJSONStream(db, resp.Body)
}

// importVulnrichment downloads and merges CISA ADP enrichment data.
func importVulnrichment(db *bun.DB) error {
	log.Println("Downloading vulnrichment dump...")

	resp, err := http.Get(vulnrichmentURL)
	if err != nil {
		return fmt.Errorf("failed to download vulnrichment dump: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return processNDJSONStream(db, resp.Body)
}

// processNDJSONStream reads an NDJSON stream line by line and processes in batches.
func processNDJSONStream(db *bun.DB, reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024) // 10MB max line

	var batch []knowledge.GCVEItem
	totalProcessed := 0

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		item, err := parseCVERecord(line)
		if err != nil {
			continue
		}
		if item == nil {
			continue // Skip REJECTED records
		}

		batch = append(batch, *item)

		if len(batch) >= batchSize {
			if err := processBatch(db, batch); err != nil {
				log.Printf("Error processing GCVE batch: %v", err)
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
		}
		totalProcessed += len(batch)
	}

	log.Printf("GCVE: total %d CVE records processed", totalProcessed)
	return scanner.Err()
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

// parseCVERecord transforms the raw CVE Record v5.x JSON into a GCVEItem.
func parseCVERecord(data []byte) (*knowledge.GCVEItem, error) {
	var raw CVERecordRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	// Skip REJECTED records
	if raw.CveMetadata.State == "REJECTED" {
		return nil, nil
	}

	item := &knowledge.GCVEItem{
		GCVEId:        raw.CveMetadata.CveId,
		CVEId:         raw.CveMetadata.CveId,
		DataVersion:   raw.DataVersion,
		State:         raw.CveMetadata.State,
		DatePublished: raw.CveMetadata.DatePublished,
		DateUpdated:   raw.CveMetadata.DateUpdated,
		AssignerOrgId: raw.CveMetadata.AssignerOrgId,
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

	// Build affected_flattened for JSONB containment queries
	item.AffectedFlattened = buildAffectedFlattened(item.Affected)

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

			// Also add ADP affected products to the flattened index
			for _, aff := range gcveAdp.Affected {
				if aff.Product != "" {
					item.AffectedFlattened = append(item.AffectedFlattened, knowledge.GCVEProduct{
						Vendor:  aff.Vendor,
						Product: aff.Product,
					})
				}
			}
		}
	}

	// Ensure empty slices instead of nil for JSONB storage
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

	return item, nil
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
func processBatch(db *bun.DB, batch []knowledge.GCVEItem) error {
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
	pkgVulns := extractPackageVulnerabilities(batch, gcveIdToUUID)
	if len(pkgVulns) > 0 {
		if err := pgsql.BatchInsertGcvePackageVulnerabilities(db, pkgVulns); err != nil {
			log.Printf("Error inserting GCVE package vulnerabilities: %v", err)
		}
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

// incrementalUpdate fetches recently modified vulnerabilities via the API.
func incrementalUpdate(db *bun.DB, since time.Time) error {
	log.Printf("GCVE incremental update since %s", since.Format(time.RFC3339))

	apiKey := os.Getenv("VULNERABILITY_LOOKUP_API_KEY")

	req, err := http.NewRequest("GET", lastUpdatedAPI, nil)
	if err != nil {
		return err
	}
	if apiKey != "" && apiKey != "!ChangeMe!" {
		req.Header.Set("X-API-KEY", apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch recent vulnerabilities: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// The /api/last endpoint returns an array of vulnerability records
	var records []json.RawMessage
	if err := json.Unmarshal(body, &records); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	var batch []knowledge.GCVEItem
	processed := 0

	for _, record := range records {
		item, err := parseCVERecord(record)
		if err != nil || item == nil {
			continue
		}

		batch = append(batch, *item)

		if len(batch) >= batchSize {
			if err := processBatch(db, batch); err != nil {
				log.Printf("Error processing incremental GCVE batch: %v", err)
			}
			processed += len(batch)
			batch = batch[:0]
		}
	}

	if len(batch) > 0 {
		if err := processBatch(db, batch); err != nil {
			log.Printf("Error processing final incremental GCVE batch: %v", err)
		}
		processed += len(batch)
	}

	log.Printf("GCVE incremental update: %d records processed", processed)
	return nil
}
