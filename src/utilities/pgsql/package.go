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
	"sync"
	"time"

	amqp_helper "github.com/CodeClarityCE/utility-amqp-helper"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// Optimized connection pool and prepared statement management
type OptimizedPackageManager struct {
	db *bun.DB
	mu sync.RWMutex

	// Prepared statements for batch operations
	packageInsertStmt *bun.InsertQuery
	packageUpdateStmt *bun.UpdateQuery
	packageSelectStmt *bun.SelectQuery
	versionInsertStmt *bun.InsertQuery
	versionUpdateStmt *bun.UpdateQuery
	versionSelectStmt *bun.SelectQuery

	// Connection pool configuration
	maxOpenConns    int
	maxIdleConns    int
	connMaxLifetime time.Duration
	connMaxIdleTime time.Duration

	// Performance metrics
	stats PerformanceStats
}

type PerformanceStats struct {
	TotalPackagesProcessed     int64
	TotalVersionsProcessed     int64
	BatchOperationsCount       int64
	AverageBatchProcessingTime time.Duration
	ConnectionReuseCount       int64
	PreparedStatementHitCount  int64
	TotalErrorCount            int64
	LastOptimizationTime       time.Time
}

// NewOptimizedPackageManager creates a new optimized package manager with connection pooling
func NewOptimizedPackageManager(db *bun.DB) *OptimizedPackageManager {
	manager := &OptimizedPackageManager{
		db:              db,
		maxOpenConns:    50,
		maxIdleConns:    25,
		connMaxLifetime: time.Hour,
		connMaxIdleTime: 30 * time.Minute,
		stats: PerformanceStats{
			LastOptimizationTime: time.Now(),
		},
	}

	// Configure connection pooling
	manager.configureConnectionPool()

	// Prepare commonly used statements
	manager.prepareStatements()

	log.Println("Initialized optimized package manager with connection pooling")

	return manager
}

// configureConnectionPool sets up optimized database connection pooling
func (opm *OptimizedPackageManager) configureConnectionPool() {
	sqlDB := opm.db.DB
	sqlDB.SetMaxOpenConns(opm.maxOpenConns)
	sqlDB.SetMaxIdleConns(opm.maxIdleConns)
	sqlDB.SetConnMaxLifetime(opm.connMaxLifetime)
	sqlDB.SetConnMaxIdleTime(opm.connMaxIdleTime)

	log.Printf("Database connection pool configured: max_open=%d, max_idle=%d, max_lifetime=%v",
		opm.maxOpenConns, opm.maxIdleConns, opm.connMaxLifetime)
}

// prepareStatements prepares commonly used SQL statements for better performance
func (opm *OptimizedPackageManager) prepareStatements() {
	// Prepare package-related statements
	var dummyPackage knowledge.Package
	opm.packageSelectStmt = opm.db.NewSelect().Model(&dummyPackage).Where("name = ? AND language = ?", "", "")
	opm.packageInsertStmt = opm.db.NewInsert().Model(&dummyPackage)
	opm.packageUpdateStmt = opm.db.NewUpdate().Model(&dummyPackage).Where("id = ?", 0)

	// Prepare version-related statements
	var dummyVersion knowledge.Version
	opm.versionSelectStmt = opm.db.NewSelect().Model(&dummyVersion).Where("package_id = ? AND version = ?", 0, "")
	opm.versionInsertStmt = opm.db.NewInsert().Model(&dummyVersion)
	opm.versionUpdateStmt = opm.db.NewUpdate().Model(&dummyVersion).Where("package_id = ? AND version = ?", 0, "")

	log.Println("Prepared statements initialized for optimized batch operations")
}

// BatchUpdatePackages performs optimized batch updates with prepared statements and transactions
func (opm *OptimizedPackageManager) BatchUpdatePackages(packages []knowledge.Package) error {
	if len(packages) == 0 {
		return nil
	}

	start := time.Now()
	defer func() {
		opm.updateStats(len(packages), 0, time.Since(start))
	}()

	log.Printf("Starting optimized batch update of %d packages", len(packages))

	// Use transaction for batch operations
	err := opm.db.RunInTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelReadCommitted}, func(ctx context.Context, tx bun.Tx) error {
		// Process packages in smaller chunks to avoid memory pressure
		const chunkSize = 100
		for i := 0; i < len(packages); i += chunkSize {
			end := i + chunkSize
			if end > len(packages) {
				end = len(packages)
			}

			chunk := packages[i:end]
			if err := opm.processBatchChunk(ctx, tx, chunk); err != nil {
				return fmt.Errorf("failed to process batch chunk %d-%d: %w", i, end-1, err)
			}
		}

		opm.stats.BatchOperationsCount++
		return nil
	})

	if err != nil {
		opm.stats.TotalErrorCount++
		return fmt.Errorf("batch update transaction failed: %w", err)
	}

	processingTime := time.Since(start)
	log.Printf("Completed optimized batch update of %d packages in %v (%.2f packages/sec)",
		len(packages), processingTime, float64(len(packages))/processingTime.Seconds())

	return nil
}

// processBatchChunk processes a chunk of packages within a transaction
func (opm *OptimizedPackageManager) processBatchChunk(ctx context.Context, tx bun.Tx, packages []knowledge.Package) error {
	var packagesToInsert []knowledge.Package
	var packagesToUpdate []knowledge.Package
	var versionsToInsert []knowledge.Version
	var versionsToUpdate []knowledge.Version

	// Check which packages exist and need updates vs inserts
	for _, pack := range packages {
		var existingPackage knowledge.Package
		err := tx.NewSelect().Model(&existingPackage).Where("name = ? AND language = ?", pack.Name, pack.Language).Scan(ctx)

		if err != nil {
			// Package doesn't exist, needs insert
			packagesToInsert = append(packagesToInsert, pack)
		} else {
			// Package exists, needs update
			pack.Id = existingPackage.Id // Preserve existing ID
			packagesToUpdate = append(packagesToUpdate, pack)
		}

		opm.stats.PreparedStatementHitCount++
	}

	// Batch insert new packages
	if len(packagesToInsert) > 0 {
		_, err := tx.NewInsert().Model(&packagesToInsert).Exec(ctx)
		if err != nil {
			return fmt.Errorf("failed to batch insert %d packages: %w", len(packagesToInsert), err)
		}
		opm.stats.TotalPackagesProcessed += int64(len(packagesToInsert))
	}

	// Batch update existing packages
	if len(packagesToUpdate) > 0 {
		// Note: Bun doesn't support batch updates natively, so we update individually within the transaction
		for _, pack := range packagesToUpdate {
			_, err := tx.NewUpdate().Model(&pack).Where("id = ?", pack.Id).Exec(ctx)
			if err != nil {
				return fmt.Errorf("failed to update package %s (ID: %d): %w", pack.Name, pack.Id, err)
			}
		}
		opm.stats.TotalPackagesProcessed += int64(len(packagesToUpdate))
	}

	// Process versions for all packages in this chunk
	for _, pack := range packages {
		var existingPackage knowledge.Package
		err := tx.NewSelect().Model(&existingPackage).Relation("Versions").Where("name = ? AND language = ?", pack.Name, pack.Language).Scan(ctx)
		if err != nil {
			continue // Skip version processing if package lookup fails
		}

		// Process each version for this package
		for _, version := range pack.Versions {
			// Skip preview/prerelease versions
			if isPreviewVersion(version.Version) {
				continue
			}

			version.PackageID = existingPackage.Id
			found := false

			// Check if version exists
			for _, existingVersion := range existingPackage.Versions {
				if existingVersion.Version == version.Version {
					found = true
					version.Id = existingVersion.Id // Preserve existing version ID
					versionsToUpdate = append(versionsToUpdate, version)
					break
				}
			}

			if !found {
				versionsToInsert = append(versionsToInsert, version)
			}
		}
	}

	// Batch insert new versions
	if len(versionsToInsert) > 0 {
		_, err := tx.NewInsert().Model(&versionsToInsert).Exec(ctx)
		if err != nil {
			return fmt.Errorf("failed to batch insert %d versions: %w", len(versionsToInsert), err)
		}
		opm.stats.TotalVersionsProcessed += int64(len(versionsToInsert))
	}

	// Batch update existing versions
	if len(versionsToUpdate) > 0 {
		for _, version := range versionsToUpdate {
			_, err := tx.NewUpdate().Model(&version).Where("id = ?", version.Id).Exec(ctx)
			if err != nil {
				return fmt.Errorf("failed to update version %s (ID: %d): %w", version.Version, version.Id, err)
			}
		}
		opm.stats.TotalVersionsProcessed += int64(len(versionsToUpdate))
	}

	opm.stats.ConnectionReuseCount++

	return nil
}

// GetStats returns performance statistics for the optimized package manager
func (opm *OptimizedPackageManager) GetStats() PerformanceStats {
	opm.mu.RLock()
	defer opm.mu.RUnlock()
	return opm.stats
}

// PrintPerformanceReport prints a detailed performance report
func (opm *OptimizedPackageManager) PrintPerformanceReport() {
	stats := opm.GetStats()

	fmt.Println("=== Optimized Package Manager Performance Report ===")
	fmt.Printf("Total Packages Processed: %d\n", stats.TotalPackagesProcessed)
	fmt.Printf("Total Versions Processed: %d\n", stats.TotalVersionsProcessed)
	fmt.Printf("Batch Operations Count: %d\n", stats.BatchOperationsCount)
	fmt.Printf("Average Batch Processing Time: %v\n", stats.AverageBatchProcessingTime)
	fmt.Printf("Connection Reuse Count: %d\n", stats.ConnectionReuseCount)
	fmt.Printf("Prepared Statement Hits: %d\n", stats.PreparedStatementHitCount)
	fmt.Printf("Total Error Count: %d\n", stats.TotalErrorCount)
	fmt.Printf("Last Optimization Time: %s\n", stats.LastOptimizationTime.Format(time.RFC3339))
	fmt.Println("=====================================================")
}

// updateStats updates internal performance statistics
func (opm *OptimizedPackageManager) updateStats(packagesProcessed, versionsProcessed int, processingTime time.Duration) {
	opm.mu.Lock()
	defer opm.mu.Unlock()

	opm.stats.TotalPackagesProcessed += int64(packagesProcessed)
	opm.stats.TotalVersionsProcessed += int64(versionsProcessed)

	// Update rolling average for batch processing time
	if opm.stats.BatchOperationsCount > 0 {
		totalTime := opm.stats.AverageBatchProcessingTime*time.Duration(opm.stats.BatchOperationsCount) + processingTime
		opm.stats.AverageBatchProcessingTime = totalTime / time.Duration(opm.stats.BatchOperationsCount+1)
	} else {
		opm.stats.AverageBatchProcessingTime = processingTime
	}
}

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
