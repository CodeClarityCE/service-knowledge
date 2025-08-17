// Package php_security provides functionality to update PHP security advisories from FriendsOfPHP
// Security Advisories Database in the knowledge database.
package php_security

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// PackagistSecurityResponse represents the response from Packagist security advisories API
type PackagistSecurityResponse struct {
	Advisories map[string][]PackagistAdvisory `json:"advisories"`
}

// PackagistAdvisory represents a single security advisory from Packagist
type PackagistAdvisory struct {
	AdvisoryID         string                   `json:"advisoryId"`
	PackageName        string                   `json:"packageName"`
	RemoteID           string                   `json:"remoteId"`
	Title              string                   `json:"title"`
	Link               string                   `json:"link"`
	CVE                string                   `json:"cve"`
	AffectedVersions   string                   `json:"affectedVersions"`
	Source             string                   `json:"source"`
	ReportedAt         string                   `json:"reportedAt"`
	ComposerRepository string                   `json:"composerRepository"`
	Severity           *string                  `json:"severity"`
	Sources            []PackagistAdvisorySource `json:"sources"`
}

// PackagistAdvisorySource represents the source of an advisory
type PackagistAdvisorySource struct {
	Name     string `json:"name"`
	RemoteID string `json:"remoteId"`
}


// Update updates the PHP security advisories from FriendsOfPHP
func Update(db *bun.DB) error {
	log.Println("Starting FriendsOfPHP security advisories update")

	// Update FriendsOfPHP Security Advisories
	if err := updateFriendsOfPHPAdvisories(db); err != nil {
		log.Printf("Error updating FriendsOfPHP advisories: %v", err)
		return err
	}

	log.Println("FriendsOfPHP security advisories update completed")
	return nil
}

// updateFriendsOfPHPAdvisories fetches and processes security advisories from Packagist
func updateFriendsOfPHPAdvisories(db *bun.DB) error {
	log.Println("Updating FriendsOfPHP Security Advisories from Packagist")

	// Note: In a full implementation, you would:
	// 1. Get list of all packages from analyzed projects
	// 2. Query Packagist for packages that exist in your database
	// For demonstration, we'll use a comprehensive list of popular PHP packages
	
	popularPackages := []string{
		"symfony/symfony",
		"symfony/http-foundation",
		"symfony/security-core",
		"laravel/framework",
		"laravel/sanctum",
		"doctrine/orm",
		"doctrine/dbal",
		"guzzlehttp/guzzle",
		"guzzlehttp/psr7",
		"monolog/monolog",
		"phpmailer/phpmailer",
		"wordpress/wordpress",
		"drupal/core",
		"slim/slim",
		"cakephp/cakephp",
		"yiisoft/yii2",
		"laminas/laminas-mvc",
		"codeigniter4/framework",
		"phpunit/phpunit",
		"composer/composer",
	}

	// Batch requests for efficiency (Packagist supports multiple packages per request)
	batchSize := 10
	for i := 0; i < len(popularPackages); i += batchSize {
		end := i + batchSize
		if end > len(popularPackages) {
			end = len(popularPackages)
		}
		batch := popularPackages[i:end]
		
		log.Printf("Fetching advisories for batch %d-%d of %d packages", i+1, end, len(popularPackages))
		if err := fetchBatchAdvisories(db, batch); err != nil {
			log.Printf("Error fetching batch advisories: %v", err)
			// Continue with next batch
		}
	}

	return nil
}

// fetchBatchAdvisories fetches advisories for multiple packages from Packagist
func fetchBatchAdvisories(db *bun.DB, packages []string) error {
	// Build URL with multiple packages
	url := "https://packagist.org/api/security-advisories/?"
	for i, pkg := range packages {
		if i > 0 {
			url += "&"
		}
		url += fmt.Sprintf("packages[]=%s", pkg)
	}
	
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch advisories: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP error %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var response PackagistSecurityResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Process advisories for all packages in the batch
	totalAdvisories := 0
	for packageName, advisories := range response.Advisories {
		for _, advisory := range advisories {
			dbAdvisory := convertPackagistToDBModel(advisory)
			if err := pgsql.UpdateFriendsOfPHP(db, dbAdvisory); err != nil {
				log.Printf("Error inserting advisory %s: %v", advisory.AdvisoryID, err)
			}
		}
		if len(advisories) > 0 {
			log.Printf("  - %s: %d advisories", packageName, len(advisories))
			totalAdvisories += len(advisories)
		}
	}
	
	if totalAdvisories > 0 {
		log.Printf("Total advisories in batch: %d", totalAdvisories)
	}

	return nil
}


// convertPackagistToDBModel converts a Packagist advisory to database model
func convertPackagistToDBModel(advisory PackagistAdvisory) knowledge.FriendsOfPHPAdvisory {
	// Parse affected versions into branches format
	branches := make(map[string]knowledge.AdvisoryBranch)
	if advisory.AffectedVersions != "" {
		branches["affected"] = knowledge.AdvisoryBranch{
			Versions: []string{advisory.AffectedVersions},
			Time:     advisory.ReportedAt,
		}
	}

	return knowledge.FriendsOfPHPAdvisory{
		AdvisoryId:  advisory.AdvisoryID,
		Title:       advisory.Title,
		CVE:         advisory.CVE,
		Link:        advisory.Link,
		Reference:   advisory.RemoteID,
		Composer:    advisory.PackageName,
		Description: advisory.Title, // Packagist doesn't provide separate description
		Branches:    branches,
		Published:   advisory.ReportedAt,
		Modified:    time.Now().Format(time.RFC3339),
	}
}

