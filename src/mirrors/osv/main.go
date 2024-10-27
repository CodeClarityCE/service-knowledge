// Package osv provides functionality to update the licenses in the OSV (Open Source Vulnerabilities) database for different ecosystems.
// It retrieves the license information from the corresponding zip files for each ecosystem and updates the database accordingly.
package osv

import (
	"archive/zip"
	"bytes"
	"encoding/json"
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

	log.Println("Start updating Licenses OSV")
	bar := progressbar.Default(int64(len(ecosystems)))

	for _, ecosystem := range ecosystems {
		url := "https://osv-vulnerabilities.storage.googleapis.com/" + ecosystem + "/all.zip"
		resp, err := http.Get(url)
		if err != nil {
			log.Println(err)
			return err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Println(err)
			return err
		}

		zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if err != nil {
			log.Println(err)
			return err
		}

		// Read all the files from zip archive
		for _, zipFile := range zipReader.File {
			// fmt.Println("Reading file:", zipFile.Name)
			unzippedFileBytes, err := readZipFile(zipFile)
			if err != nil {
				log.Println(err)
				continue
			}

			_ = unzippedFileBytes // this is unzipped file bytes
			var result knowledge.OSVItem
			json.Unmarshal(unzippedFileBytes, &result)
			// result.Key = strings.ReplaceAll(ecosystem, " ", "_") + ":" + result.Id

			cwe_ids_arr := []string{}
			cve_id := ""

			if _, ok := result.DatabaseSpecific["cwe_ids"]; ok {

				if cwes_raw, ok := result.DatabaseSpecific["cwe_ids"].([]interface{}); ok {
					for _, cwe_raw := range cwes_raw {
						if cwe_string, ok := cwe_raw.(string); ok {
							if strings.HasPrefix(cwe_string, "CWE") {
								cwe_ids_arr = append(cwe_ids_arr, cwe_string)
							}
						}
					}
				}

			}

			aliases := result.Aliases
			for _, alias := range aliases {
				if strings.HasPrefix(alias, "CVE") {
					cve_id = alias
					break
				}
			}

			result.Cve = cve_id
			result.Cwes = cwe_ids_arr

			pgsql.UpdateOsv(db, result)
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
