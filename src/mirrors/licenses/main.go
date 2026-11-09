// Package licenses provides functionality for updating licenses metadata in a graph.
// It fetches licenses from a remote source and updates them in the graph.
package licenses

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"

	"github.com/uptrace/bun"
)

// Update updates the licenses metadata in the provided graph.
// It fetches the licenses from a remote source and updates them in the graph.
// Returns an error if there is a problem when fetching or updating licenses.
func Update(db *bun.DB) error {
	return sourcesync.Run(db, knowledge.SourceLicenses, func() (time.Time, error) {
		log.Println("Start updating Licenses metadata")
		syncedAt := time.Now()

		// Get licenses
		licenses, err := downloadLicenses()
		if err != nil {
			log.Print("Problem when fetching licenses")
			return time.Time{}, err
		}

		licenses = addCodeClarityInfo(licenses)

		// Update licenses
		if err := pgsql.UpdateLicenses(db, licenses); err != nil {
			log.Print("Problem when updating licenses")
			return time.Time{}, err
		}

		ids := make([]string, len(licenses))
		for i, license := range licenses {
			ids[i] = license.LicenseID
		}
		if err := pgsql.ReconcileLicenses(db, ids); err != nil {
			return time.Time{}, err
		}
		return syncedAt, nil
	})
}

// licensesURL is the current SPDX license list.
var licensesURL = "https://raw.githubusercontent.com/spdx/license-list-data/main/json/licenses.json"

// downloadLicenses fetches licenses from a remote source and returns them as a slice of types.License.
// It makes an HTTP GET request to the specified URL and parses the response body as JSON.
// Returns the licenses and an error if there is a problem when fetching or parsing the licenses.
func downloadLicenses() ([]knowledge.License, error) {
	// Get licenses from remote source
	resp, err := http.Get(licensesURL)
	if err != nil {
		log.Println("No response from request")
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

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

	if len(result.Licenses) == 0 {
		return nil, fmt.Errorf("SPDX license list has no licenses")
	}

	return knowledge.GetDetails(result.Licenses), nil
}
