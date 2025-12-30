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
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// PackagistSecurityResponse represents the response from Packagist security advisories API
type PackagistSecurityResponse struct {
	Advisories map[string][]PackagistAdvisory `json:"advisories"`
}

// PackagistAdvisory represents a single security advisory from Packagist
type PackagistAdvisory struct {
	AdvisoryID         string                    `json:"advisoryId"`
	PackageName        string                    `json:"packageName"`
	RemoteID           string                    `json:"remoteId"`
	Title              string                    `json:"title"`
	Link               string                    `json:"link"`
	CVE                string                    `json:"cve"`
	AffectedVersions   string                    `json:"affectedVersions"`
	Source             string                    `json:"source"`
	ReportedAt         string                    `json:"reportedAt"`
	ComposerRepository string                    `json:"composerRepository"`
	Severity           *string                   `json:"severity"`
	Sources            []PackagistAdvisorySource `json:"sources"`
}

// PackagistAdvisorySource represents the source of an advisory
type PackagistAdvisorySource struct {
	Name     string `json:"name"`
	RemoteID string `json:"remoteId"`
}

// advisoryInfo holds advisory ID and package name for creating package_vulnerability links
type advisoryInfo struct {
	advisoryId  string
	packageName string
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
		end := min(i+batchSize, len(popularPackages))
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

	// Step 1: Insert advisories and collect advisory IDs with their package names
	var advisoryInfos []advisoryInfo
	totalAdvisories := 0

	for packageName, advisories := range response.Advisories {
		for _, advisory := range advisories {
			dbAdvisory := convertPackagistToDBModel(advisory)
			if err := pgsql.UpdateFriendsOfPHP(db, dbAdvisory); err != nil {
				log.Printf("Error inserting advisory %s: %v", advisory.AdvisoryID, err)
				continue
			}
			advisoryInfos = append(advisoryInfos, advisoryInfo{
				advisoryId:  advisory.AdvisoryID,
				packageName: packageName,
			})
		}
		if len(advisories) > 0 {
			log.Printf("  - %s: %d advisories", packageName, len(advisories))
			totalAdvisories += len(advisories)
		}
	}

	if totalAdvisories > 0 {
		log.Printf("Total advisories in batch: %d", totalAdvisories)
	}

	// Step 2: Get UUIDs for inserted advisories
	if len(advisoryInfos) > 0 {
		advisoryIds := make([]string, len(advisoryInfos))
		for i, info := range advisoryInfos {
			advisoryIds[i] = info.advisoryId
		}

		advisoryIdToUUID, err := pgsql.GetFriendsOfPhpUUIDsByAdvisoryIds(db, advisoryIds)
		if err != nil {
			log.Printf("Error getting FriendsOfPHP UUIDs: %v", err)
			return nil // Don't fail the whole batch
		}

		// Step 3: Create package_vulnerability records
		pkgVulns := extractPackageVulnerabilitiesFromFriendsOfPhp(advisoryInfos, advisoryIdToUUID)
		if len(pkgVulns) > 0 {
			if err := pgsql.BatchInsertFriendsOfPhpPackageVulnerabilities(db, pkgVulns); err != nil {
				log.Printf("Error inserting package vulnerabilities from FriendsOfPHP: %v", err)
			}
		}
	}

	return nil
}

// extractPackageVulnerabilitiesFromFriendsOfPhp creates package-vulnerability links from FriendsOfPHP advisories.
func extractPackageVulnerabilitiesFromFriendsOfPhp(advisoryInfos []advisoryInfo, advisoryIdToUUID map[string]uuid.UUID) []knowledge.PackageVulnerability {
	var pkgVulns []knowledge.PackageVulnerability
	seen := make(map[string]bool)

	for _, info := range advisoryInfos {
		fopUUID, ok := advisoryIdToUUID[info.advisoryId]
		if !ok {
			continue
		}

		// Create unique key for deduplication
		key := fmt.Sprintf("%s:packagist:%s", info.packageName, info.advisoryId)
		if seen[key] {
			continue
		}
		seen[key] = true

		pkgVuln := knowledge.PackageVulnerability{
			PackageName:      info.packageName,
			PackageEcosystem: "packagist",
			FriendsOfPhpId:   &fopUUID,
		}
		pkgVulns = append(pkgVulns, pkgVuln)
	}

	return pkgVulns
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

// Legacy types and functions for compatibility with tests

// FriendsOfPHPAdvisory represents a FriendsOfPHP advisory (legacy alias)
type FriendsOfPHPAdvisory = knowledge.FriendsOfPHPAdvisory

// AdvisoryBranch represents an advisory branch (legacy alias)
type AdvisoryBranch = knowledge.AdvisoryBranch

// PHPCoreVulnerability represents a PHP core vulnerability
type PHPCoreVulnerability struct {
	CVE         string    `json:"cve"`
	Summary     string    `json:"summary"`
	Description string    `json:"description"`
	Published   time.Time `json:"published"`
	Modified    time.Time `json:"modified"`
	Severity    string    `json:"severity"`
	CVSS        float64   `json:"cvss"`
	References  []string  `json:"references"`
	Versions    []string  `json:"versions"`
}

// convertFriendsOfPHPToOSV converts a FriendsOfPHP advisory to OSV format
func convertFriendsOfPHPToOSV(id string, advisory FriendsOfPHPAdvisory) knowledge.OSVItem {
	// Extract affected versions from branches
	var affectedVersions []string
	for _, branch := range advisory.Branches {
		affectedVersions = append(affectedVersions, branch.Versions...)
	}

	// Create OSV affected entry
	affected := []knowledge.Affected{
		{
			Package: knowledge.OSVPackage{
				Ecosystem: "Packagist",
				Name:      advisory.Composer,
			},
			Versions: affectedVersions,
		},
	}

	// Create references
	references := []knowledge.Reference{
		{
			Type: "ADVISORY",
			Url:  advisory.Link,
		},
	}
	if advisory.Reference != "" {
		references = append(references, knowledge.Reference{
			Type: "WEB",
			Url:  advisory.Reference,
		})
	}

	// Set aliases (CVE if available)
	var aliases []string
	if advisory.CVE != "" {
		aliases = append(aliases, advisory.CVE)
	}

	return knowledge.OSVItem{
		OSVId:      "FRIENDSOFPHP-" + id,
		Summary:    advisory.Title,
		Details:    advisory.Description,
		Aliases:    aliases,
		Published:  advisory.Published,
		Modified:   advisory.Modified,
		References: references,
		Affected:   affected,
		DatabaseSpecific: map[string]any{
			"source":      "FriendsOfPHP",
			"advisory_id": advisory.AdvisoryId,
		},
	}
}

// convertPHPCoreToOSV converts a PHP core vulnerability to OSV format
func convertPHPCoreToOSV(vuln PHPCoreVulnerability) knowledge.OSVItem {
	// Create OSV affected entry for PHP core
	affected := []knowledge.Affected{
		{
			Package: knowledge.OSVPackage{
				Ecosystem: "PHP-Core",
				Name:      "php",
			},
			Versions: vuln.Versions,
		},
	}

	// Create references
	references := []knowledge.Reference{}
	for _, ref := range vuln.References {
		references = append(references, knowledge.Reference{
			Type: "WEB",
			Url:  ref,
		})
	}

	// Create severity
	severity := []knowledge.Severity{
		{
			Type:  "CVSS_V3",
			Score: fmt.Sprintf("%.1f", vuln.CVSS),
		},
	}

	// Set aliases
	var aliases []string
	if vuln.CVE != "" {
		aliases = append(aliases, vuln.CVE)
	}

	return knowledge.OSVItem{
		OSVId:      vuln.CVE,
		Summary:    vuln.Summary,
		Details:    vuln.Description,
		Aliases:    aliases,
		Published:  vuln.Published.Format(time.RFC3339),
		Modified:   vuln.Modified.Format(time.RFC3339),
		References: references,
		Affected:   affected,
		Severity:   severity,
		DatabaseSpecific: map[string]any{
			"source":   "PHP-Core",
			"severity": vuln.Severity,
		},
	}
}

// createSamplePHPCoreVulnerabilities creates sample PHP core vulnerabilities for testing
func createSamplePHPCoreVulnerabilities(_ string) []PHPCoreVulnerability {
	return []PHPCoreVulnerability{
		{
			CVE:         "CVE-2024-PHP-001",
			Summary:     "Buffer overflow in PHP core",
			Description: "A buffer overflow vulnerability was found in PHP core that could lead to remote code execution",
			Published:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			Modified:    time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
			Severity:    "HIGH",
			CVSS:        7.5,
			References:  []string{"https://php.net/security", "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-PHP-001"},
			Versions:    []string{"< 8.3.0"},
		},
	}
}
