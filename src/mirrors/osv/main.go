// Package osv provides functionality to update the licenses in the OSV (Open Source Vulnerabilities) database for different ecosystems.
// It retrieves the license information from the corresponding zip files for each ecosystem and updates the database accordingly.
package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	config "github.com/CodeClarityCE/utility-types/config_db"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
	"github.com/schollz/progressbar/v3"
	"github.com/uptrace/bun"
)

// ImportedEcosystems is the ecosystem scope of the OSV mirror. The as-of
// importer (src/mirrors/osv_asof) derives its scope from this list too, so the
// two importers always cover the same ecosystems.
var ImportedEcosystems = []string{
	// "Alpine",
	// "Alpine:v3.10",
	// "Alpine:v3.11",
	// "Alpine:v3.12",
	// "Alpine:v3.13",
	// "Alpine:v3.14",
	// "Alpine:v3.15",
	// "Alpine:v3.16",
	// "Alpine:v3.17",
	// "Alpine:v3.2",
	// "Alpine:v3.3",
	// "Alpine:v3.4",
	// "Alpine:v3.5",
	// "Alpine:v3.6",
	// "Alpine:v3.7",
	// "Alpine:v3.8",
	// "Alpine:v3.9",
	// "Android",
	// "Debian",
	// "Debian:10",
	// "Debian:11",
	// "Debian:3.0",
	// "Debian:3.1",
	// "Debian:4.0",
	// "Debian:5.0",
	// "Debian:6.0",
	// "Debian:7",
	// "Debian:8",
	// "Debian:9",
	// "GSD",
	// "GitHub Actions",
	// "Go",
	// "Hex",
	// "Linux",
	// "Maven",
	// "NuGet",
	// "OSS-Fuzz",
	"Packagist",
	// "Pub",
	// "PyPI",
	// "RubyGems",
	// "UVI",
	// "crates.io",
	"npm",
}

// Update updates the licenses in the OSV (Open Source Vulnerabilities) database for the specified ecosystems.
// It retrieves the license information from the corresponding zip files for each ecosystem and updates the database accordingly.
// The function takes a graph driver as a parameter and returns an error if any occurred during the update process.
func Update(db *bun.DB, db_config *bun.DB) error {
	log.Println("Start updating OSV vulnerabilities")
	bar := progressbar.Default(int64(len(ImportedEcosystems)))

	for _, ecosystem := range ImportedEcosystems {
		log.Printf("Processing ecosystem: %s", ecosystem)
		url := "https://osv-vulnerabilities.storage.googleapis.com/" + ecosystem + "/all.zip"

		if err := processEcosystem(db, ecosystem, url); err != nil {
			log.Printf("Error processing ecosystem %s: %v", ecosystem, err)
			// Continue with other ecosystems even if one fails
		}

		bar.Add(1)
	}

	return SetLastOSVSync(db_config, time.Now())
}

// SetLastOSVSync stamps osv_last on the shared config row. The update is
// column-scoped (not a full-row save like nvd/gcve) so concurrent writers of
// the other *_last columns are not clobbered. The as-of importer
// (src/mirrors/osv_asof) reuses it to stamp the advisory-checkout commit date.
func SetLastOSVSync(db_config *bun.DB, syncedAt time.Time) error {
	ctx := context.Background()
	var configs []config.Config
	err := db_config.NewSelect().Model(&configs).Limit(1).Scan(ctx)
	if err != nil {
		log.Println("Can't get config for OSV sync", err)
		return err
	}
	if len(configs) == 0 {
		return fmt.Errorf("no config found")
	}
	conf := configs[0]
	conf.OsvLast = syncedAt
	_, err = db_config.NewUpdate().Model(&conf).Column("osv_last").Where("id = ?", conf.Id).Exec(ctx)
	if err != nil {
		log.Println("Failed to update OSV sync timestamp:", err)
		return err
	}
	return nil
}

// readZipFile reads the contents of a zip file entry and returns it as a byte slice.
// It takes a pointer to a zip.File as input and returns the read data and any error encountered.
func readZipFile(zf *zip.File) ([]byte, error) {
	f, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// ParseAdvisory converts a raw OSV advisory JSON document into a
// knowledge.OSVItem with the mirror's derived-field semantics: cwes from
// database_specific.cwe_ids and cve from the first CVE alias; the vlai_*
// fields keep their zero values. It is the single transform shared by the
// live GCS import below and the as-of importer (src/mirrors/osv_asof).
func ParseAdvisory(data []byte) (knowledge.OSVItem, error) {
	var result knowledge.OSVItem
	if err := json.Unmarshal(data, &result); err != nil {
		return knowledge.OSVItem{}, err
	}

	// Extract CWE IDs and CVE ID efficiently
	result.Cwes = extractCWEIds(result.DatabaseSpecific)
	result.Cve = extractCVEId(result.Aliases)

	return result, nil
}

// extractCWEIds efficiently extracts CWE IDs from the database specific field
func extractCWEIds(databaseSpecific map[string]any) []string {
	if databaseSpecific == nil {
		return nil
	}

	cweIds, ok := databaseSpecific["cwe_ids"]
	if !ok {
		return nil
	}

	cwesRaw, ok := cweIds.([]interface{})
	if !ok {
		return nil
	}

	var result []string
	for _, cweRaw := range cwesRaw {
		if cweString, ok := cweRaw.(string); ok && strings.HasPrefix(cweString, "CWE") {
			result = append(result, cweString)
		}
	}

	return result
}

// extractCVEId efficiently extracts the first CVE ID from aliases
func extractCVEId(aliases []string) string {
	for _, alias := range aliases {
		if strings.HasPrefix(alias, "CVE") {
			return alias
		}
	}
	return ""
}

// mapOSVEcosystem maps OSV ecosystem names to our internal format
func mapOSVEcosystem(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return "npm"
	case "packagist":
		return "packagist"
	default:
		return strings.ToLower(ecosystem)
	}
}

// extractPackageVulnerabilities extracts package-vulnerability relationships from OSV items.
// Uses the osvIdToUUID map to set the FK reference to the OSV table.
func extractPackageVulnerabilities(osvItems []knowledge.OSVItem, osvIdToUUID map[string]uuid.UUID) []knowledge.PackageVulnerability {
	var pkgVulns []knowledge.PackageVulnerability

	for _, osv := range osvItems {
		// Look up the UUID for this OSV record
		osvUUID, ok := osvIdToUUID[osv.OSVId]
		if !ok {
			// Skip if we don't have the UUID (shouldn't happen normally)
			continue
		}

		for _, affected := range osv.Affected {
			if affected.Package.Name == "" {
				continue
			}

			pkgVuln := knowledge.PackageVulnerability{
				PackageName:      affected.Package.Name,
				PackageEcosystem: mapOSVEcosystem(affected.Package.Ecosystem),
				OsvId:            &osvUUID,
			}
			pkgVulns = append(pkgVulns, pkgVuln)
		}
	}

	return pkgVulns
}

// processEcosystem downloads and processes vulnerabilities for a single ecosystem
func processEcosystem(db *bun.DB, ecosystem, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return fmt.Errorf("failed to read zip archive: %w", err)
	}

	// Process files in batches for better performance
	const batchSize = 100
	var osvBatch []knowledge.OSVItem

	// Read all the files from zip archive
	for _, zipFile := range zipReader.File {
		unzippedFileBytes, err := readZipFile(zipFile)
		if err != nil {
			log.Printf("Error reading zip file %s: %v", zipFile.Name, err)
			continue
		}

		result, err := ParseAdvisory(unzippedFileBytes)
		if err != nil {
			log.Printf("Error unmarshaling JSON from %s: %v", zipFile.Name, err)
			continue
		}

		// Add to batch
		osvBatch = append(osvBatch, result)

		// Process batch when it reaches the desired size
		if len(osvBatch) >= batchSize {
			if err := InsertBatch(db, osvBatch, ecosystem); err != nil {
				log.Printf("Error processing batch for ecosystem %s: %v", ecosystem, err)
			}
			osvBatch = osvBatch[:0] // Reset slice but keep capacity
		}
	}

	// Process remaining items in the batch
	if len(osvBatch) > 0 {
		if err := InsertBatch(db, osvBatch, ecosystem); err != nil {
			log.Printf("Error processing final batch for ecosystem %s: %v", ecosystem, err)
		}
	}

	return nil
}

// InsertBatch inserts OSV records and creates package-vulnerability links.
// It is shared by the live GCS import and the as-of importer so stored rows
// and package links are produced identically.
func InsertBatch(db *bun.DB, osvBatch []knowledge.OSVItem, ecosystem string) error {
	// Step 1: Insert OSV records
	if err := pgsql.BatchUpdateOsv(db, osvBatch); err != nil {
		return fmt.Errorf("batch update failed: %w", err)
	}

	// Step 2: Get UUIDs for the inserted OSV records
	osvIds := make([]string, len(osvBatch))
	for i, osv := range osvBatch {
		osvIds[i] = osv.OSVId
	}

	osvIdToUUID, err := pgsql.GetOsvUUIDsByOsvIds(db, osvIds)
	if err != nil {
		return fmt.Errorf("failed to get OSV UUIDs: %w", err)
	}

	// Step 3: Extract and insert package-vulnerability relationships with FK
	pkgVulns := extractPackageVulnerabilities(osvBatch, osvIdToUUID)
	if len(pkgVulns) > 0 {
		if err := pgsql.BatchInsertOsvPackageVulnerabilities(db, pkgVulns); err != nil {
			log.Printf("Error inserting package vulnerabilities for ecosystem %s: %v", ecosystem, err)
		}
	}

	return nil
}
