// Package osv provides functionality to update the licenses in the OSV (Open Source Vulnerabilities) database for different ecosystems.
// It retrieves the license information from the corresponding zip files for each ecosystem and updates the database accordingly.
package osv

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/schollz/progressbar/v3"
	"github.com/uptrace/bun"
)

// Update updates the licenses in the OSV (Open Source Vulnerabilities) database for the specified ecosystems.
// It retrieves the license information from the corresponding zip files for each ecosystem and updates the database accordingly.
// The function takes a graph driver as a parameter and returns an error if any occurred during the update process.
func Update(db *bun.DB) error {
	ecosystems := []string{
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
		// "Packagist",
		// "Pub",
		// "PyPI",
		// "RubyGems",
		// "UVI",
		// "crates.io",
		"npm",
	}

	log.Println("Start updating OSV vulnerabilities")
	bar := progressbar.Default(int64(len(ecosystems)))

	for _, ecosystem := range ecosystems {
		log.Printf("Processing ecosystem: %s", ecosystem)
		url := "https://osv-vulnerabilities.storage.googleapis.com/" + ecosystem + "/all.zip"

		if err := processEcosystem(db, ecosystem, url); err != nil {
			log.Printf("Error processing ecosystem %s: %v", ecosystem, err)
			// Continue with other ecosystems even if one fails
		}

		bar.Add(1)
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

		var result knowledge.OSVItem
		if err := json.Unmarshal(unzippedFileBytes, &result); err != nil {
			log.Printf("Error unmarshaling JSON from %s: %v", zipFile.Name, err)
			continue
		}

		// Extract CWE IDs and CVE ID efficiently
		result.Cwes = extractCWEIds(result.DatabaseSpecific)
		result.Cve = extractCVEId(result.Aliases)

		// Add to batch
		osvBatch = append(osvBatch, result)

		// Process batch when it reaches the desired size
		if len(osvBatch) >= batchSize {
			if err := pgsql.BatchUpdateOsv(db, osvBatch); err != nil {
				log.Printf("Error in batch update for ecosystem %s: %v", ecosystem, err)
			}
			osvBatch = osvBatch[:0] // Reset slice but keep capacity
		}
	}

	// Process remaining items in the batch
	if len(osvBatch) > 0 {
		if err := pgsql.BatchUpdateOsv(db, osvBatch); err != nil {
			log.Printf("Error in final batch update for ecosystem %s: %v", ecosystem, err)
		}
	}

	return nil
}
