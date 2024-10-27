// Package licenses provides functionality for updating licenses metadata in a graph.
// It fetches licenses from a remote source and updates them in the graph.
package licenses

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"

	"github.com/uptrace/bun"
)

// Update updates the licenses metadata in the provided graph.
// It fetches the licenses from a remote source and updates them in the graph.
// Returns an error if there is a problem when fetching or updating licenses.
func Update(db *bun.DB) error {
	log.Println("Start updating Licenses metadata")

	// Get licenses
	licenses, err := downloadLicenses()
	if err != nil {
		log.Print("Problem when fetching licenses")
		return err
	}

	licenses = addCodeClarityInfo(licenses)

	// Update licenses
	err = pgsql.UpdateLicenses(db, licenses)
	if err != nil {
		log.Print("Problem when updating licenses")
		return err
	}
	return nil
}

// downloadLicenses fetches licenses from a remote source and returns them as a slice of types.License.
// It makes an HTTP GET request to the specified URL and parses the response body as JSON.
// Returns the licenses and an error if there is a problem when fetching or parsing the licenses.
func downloadLicenses() ([]knowledge.License, error) {
	// Get licenses from remote source
	resp, err := http.Get("https://raw.githubusercontent.com/spdx/license-list-data/main/json/licenses.json")
	if err != nil {
		log.Println("No response from request")
		return nil, err
	}
	defer resp.Body.Close()

	// Parse response body
	var result knowledge.LicenseList
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Can't read response body", err)
		return nil, err
	}

	// Unmarshal response body
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return knowledge.GetDetails(result.Licenses), nil
}
