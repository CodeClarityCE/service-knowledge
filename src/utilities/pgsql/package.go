// Package psql provides utility functions for working with Postgre in the context of a knowledge database.
package pgsql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	amqp_helper "github.com/CodeClarityCE/utility-amqp-helper"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// UpdatePackage updates a package in the specified graph with the given package information.
// It takes the graph, package details, and language as input parameters.
// If the package key is empty, it returns an error.
// If the package already exists in the graph, it updates the package and creates a revision document with the changelog.
// If the package doesn't exist, it creates a new package document.
// It also updates the versions of the package and creates edge documents to link the package with its versions.
// Returns an error if any operation fails.
func UpdatePackage(db *bun.DB, pack knowledge.Package) error {

	var existingPackage knowledge.Package
	err := db.NewSelect().Model(&existingPackage).Where("name = ? AND language = ?", pack.Name, pack.Language).Scan(context.Background())
	if err != nil {
		_, err := db.NewInsert().Model(&pack).Exec(context.Background())
		if err != nil {
			return err
		}
	} else {
		_, err = db.NewUpdate().Model(&pack).Where("id = ?", existingPackage.Id).Exec(context.Background())
		if err != nil {
			return err
		}
	}

	err = db.NewSelect().Model(&existingPackage).Relation("Versions").Where("name = ? AND language = ?", pack.Name, pack.Language).Scan(context.Background())
	if err != nil {
		return err
	}

	// Insert new versions (only stable versions)
	var newVersions []knowledge.Version
	for _, version := range pack.Versions {
		// Skip preview/prerelease versions
		if isPreviewVersion(version.Version) {
			continue
		}

		version.PackageID = existingPackage.Id
		found := false
		// Check if the version already exists
		for _, existingVersion := range existingPackage.Versions {
			if existingVersion.Version == version.Version {
				found = true
				break
			}
		}
		if !found { // If the version doesn't exist, insert it
			_, err := db.NewInsert().Model(&version).Exec(context.Background())
			if err != nil {
				return err
			}
			newVersions = append(newVersions, version)
		} else { // If the version exists, update it
			_, err := db.NewUpdate().Model(&version).Where("package_id = ? and version = ?", existingPackage.Id, version.Version).Exec(context.Background())
			if err != nil {
				return err
			}
		}
	}

	// Send notification about new package versions if found
	if len(newVersions) > 0 {
		go func() {
			err := sendPackageUpdateNotification(db, pack.Name, existingPackage.Versions, newVersions)
			if err != nil {
				log.Printf("Failed to send package update notification for %s: %v", pack.Name, err)
			}
		}()
	}

	return nil
}

// sendPackageUpdateNotification checks for SBOM results that use this package
// and sends notifications to users about available updates
func sendPackageUpdateNotification(knowledgeDB *bun.DB, packageName string, existingVersions []knowledge.Version, newVersions []knowledge.Version) error {
	// Connect to codeclarity database to check for SBOM results
	host := os.Getenv("PG_DB_HOST")
	port := os.Getenv("PG_DB_PORT")
	user := os.Getenv("PG_DB_USER")
	password := os.Getenv("PG_DB_PASSWORD")

	if host == "" || port == "" || user == "" || password == "" {
		return fmt.Errorf("database connection parameters not set")
	}

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/codeclarity?sslmode=disable", user, password, host, port)
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn), pgdriver.WithTimeout(30*time.Second)))
	codeClarityDB := bun.NewDB(sqldb, pgdialect.New())
	defer codeClarityDB.Close()

	// Find the latest version from new versions (assuming semantic versioning)
	var latestNewVersion knowledge.Version
	for _, nv := range newVersions {
		if latestNewVersion.Version == "" || compareVersions(nv.Version, latestNewVersion.Version) > 0 {
			latestNewVersion = nv
		}
	}

	// Query for SBOM results that contain this package as a direct dependency
	query := `
		SELECT DISTINCT r.id, r."analysisId", a."projectId", a."organizationId", p.name as project_name
		FROM result r 
		JOIN analysis a ON r."analysisId" = a.id
		JOIN project p ON a."projectId" = p.id
		WHERE r.plugin = 'js-sbom' 
		AND r.result::jsonb->'workspaces' @> ?::jsonb
	`

	// Build query condition to find direct dependencies
	searchCondition := fmt.Sprintf(`{"%s": {"dependencies": {"%s": {}}}}`, ".", packageName)
	rows, err := codeClarityDB.Query(query, searchCondition)
	if err != nil {
		log.Printf("Failed to query SBOM results for package %s: %v", packageName, err)
		return err
	}
	defer rows.Close()

	// Track notifications by organization to avoid duplicates
	sentNotifications := make(map[string]bool)
	// Track projects per organization for better notification context
	orgProjects := make(map[string][]string)

	for rows.Next() {
		var resultID, analysisID, projectID, organizationID, projectName string
		if err := rows.Scan(&resultID, &analysisID, &projectID, &organizationID, &projectName); err != nil {
			log.Printf("Failed to scan SBOM result: %v", err)
			continue
		}

		// Track projects for this organization
		orgProjects[organizationID] = append(orgProjects[organizationID], projectName)

		// Skip if we already sent a notification for this package to this organization
		notificationKey := fmt.Sprintf("%s-%s", packageName, organizationID)
		if sentNotifications[notificationKey] {
			continue
		}

		// Get the current version used in this project
		var result struct {
			ID     string                 `bun:"id"`
			Result map[string]interface{} `bun:"result"`
		}

		err = codeClarityDB.NewSelect().
			Table("result").
			Column("id", "result").
			Where("id = ?", resultID).
			Scan(context.Background(), &result.ID, &result.Result)
		if err != nil {
			log.Printf("Failed to get SBOM result details: %v", err)
			continue
		}

		// Extract current version and dependency type from SBOM result
		currentVersion, dependencyType := extractCurrentVersionFromSBOM(result.Result, packageName)
		if currentVersion == "" {
			continue
		}

		// Check if the new version is an upgrade
		if compareVersions(latestNewVersion.Version, currentVersion) > 0 {
			// Generate release notes URL for npm packages
			releaseNotesURL := fmt.Sprintf("https://github.com/npm/%s/releases", packageName)
			if packageName != "npm" {
				// For most packages, try to guess the GitHub URL or use npm page
				releaseNotesURL = fmt.Sprintf("https://www.npmjs.com/package/%s", packageName)
			}

			// Get project count for this organization
			projectCount := len(orgProjects[organizationID])
			var projectContext string
			if projectCount > 1 {
				projectContext = fmt.Sprintf("%s and %d other projects", projectName, projectCount-1)
			} else {
				projectContext = projectName
			}

			// Send notification message with dependency type
			notification := map[string]interface{}{
				"type":              "package_update",
				"analysis_id":       analysisID,
				"organization_id":   organizationID,
				"project_id":        projectID,
				"project_name":      projectContext,
				"package_name":      packageName,
				"current_version":   currentVersion,
				"new_version":       latestNewVersion.Version,
				"dependency_type":   dependencyType,
				"project_count":     projectCount,
				"release_notes_url": releaseNotesURL,
			}

			data, err := json.Marshal(notification)
			if err != nil {
				log.Printf("Failed to marshal notification: %v", err)
				continue
			}

			amqp_helper.Send("service_notifier", data)

			// Mark this notification as sent for this organization
			sentNotifications[notificationKey] = true
		}
	}

	return nil
}

// extractCurrentVersionFromSBOM extracts the current version of a package from SBOM result
// Returns version string and dependency type (prod/dev)
func extractCurrentVersionFromSBOM(sbomResult map[string]interface{}, packageName string) (string, string) {
	workspaces, ok := sbomResult["workspaces"].(map[string]interface{})
	if !ok {
		return "", ""
	}

	for _, workspace := range workspaces {
		ws, ok := workspace.(map[string]interface{})
		if !ok {
			continue
		}

		start, ok := ws["start"].(map[string]interface{})
		if !ok {
			continue
		}

		// Check production dependencies first
		if deps, ok := start["dependencies"].([]interface{}); ok {
			for _, dep := range deps {
				if depMap, ok := dep.(map[string]interface{}); ok {
					if name, ok := depMap["name"].(string); ok && name == packageName {
						if version, ok := depMap["version"].(string); ok {
							return version, "production"
						}
					}
				}
			}
		}

		// Check dev dependencies
		if devDeps, ok := start["dev_dependencies"].([]interface{}); ok {
			for _, dep := range devDeps {
				if depMap, ok := dep.(map[string]interface{}); ok {
					if name, ok := depMap["name"].(string); ok && name == packageName {
						if version, ok := depMap["version"].(string); ok {
							return version, "development"
						}
					}
				}
			}
		}

		// Also check the more detailed dependencies structure if available (but only for direct dependencies)
		if dependencies, ok := ws["dependencies"].(map[string]interface{}); ok {
			for depName, depData := range dependencies {
				if depName == packageName {
					if depVersions, ok := depData.(map[string]interface{}); ok {
						for version, versionData := range depVersions {
							if versionInfo, ok := versionData.(map[string]interface{}); ok {
								// Check if this is a direct dependency using DirectCount (preferred) or Direct boolean
								isDirect := false
								if directCount, ok := versionInfo["DirectCount"].(float64); ok && directCount > 0 {
									isDirect = true
								} else if direct, ok := versionInfo["Direct"].(bool); ok && direct {
									isDirect = true
								}

								if isDirect {
									// Check if this is a production dependency
									if prod, ok := versionInfo["Prod"].(bool); ok && prod {
										return version, "production"
									}
									// Check if this is a dev dependency
									if dev, ok := versionInfo["Dev"].(bool); ok && dev {
										return version, "development"
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return "", ""
}

// compareVersions compares two semantic version strings
// Returns: 1 if v1 > v2, -1 if v1 < v2, 0 if equal
func compareVersions(v1, v2 string) int {
	// Simple string comparison for now - would need proper semver parsing for production
	if v1 > v2 {
		return 1
	} else if v1 < v2 {
		return -1
	}
	return 0
}

// isPreviewVersion checks if a version string represents a preview/prerelease version
func isPreviewVersion(version string) bool {
	versionLower := strings.ToLower(version)

	previewKeywords := []string{
		"alpha", "beta", "rc", "canary", "next", "dev", "experimental",
		"preview", "pre", "snapshot", "nightly", "unstable", "-alpha",
		"-beta", "-rc", "-canary", "-next", "-dev", "-experimental",
		"-preview", "-pre", "-snapshot", "-nightly", "-unstable",
		".alpha", ".beta", ".rc", ".canary", ".next", ".dev",
		".experimental", ".preview", ".pre", ".snapshot", ".nightly",
		".unstable", "alpha.", "beta.", "rc.", "canary.", "next.", "dev.",
		"experimental.", "preview.", "pre.", "snapshot.", "nightly.", "unstable.",
	}

	for _, keyword := range previewKeywords {
		if strings.Contains(versionLower, keyword) {
			return true
		}
	}

	return false
}
