// Package js contains the functions to update the JS mirror
package js

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	"github.com/CodeClarityCE/service-knowledge/src/utilities/tools"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/schollz/progressbar/v3"
	"github.com/uptrace/bun"
)

type Config struct {
	Key  string `json:"_key"`
	Last int    `json:"last"`
}

func ImportList(db *bun.DB, topPackages []string) error {
	log.Println("Start importing JS")
	var wg sync.WaitGroup
	maxGoroutines := 10
	guard := make(chan struct{}, maxGoroutines)

	// Configure progression bar
	bar := progressbar.Default(int64(len(topPackages)))

	for _, npmPackage := range topPackages {
		wg.Add(1)
		guard <- struct{}{}
		go func(wg *sync.WaitGroup, packageName string) {
			defer wg.Done()
			defer bar.Add(1)
			// Get package
			UpdatePackage(db, packageName)

			<-guard
		}(&wg, npmPackage)
	}
	wg.Wait()
	return nil
}

// ImportListWithBatching imports a list of JavaScript packages using batch processing for improved performance
func ImportListWithBatching(db *bun.DB, topPackages []string) error {
	if len(topPackages) == 0 {
		return nil
	}

	start := time.Now()
	log.Printf("🔄 Starting batch import of %d JavaScript packages from NPM", len(topPackages))

	// Use batch processing for better database performance
	const batchSize = 50
	const maxConcurrency = 5

	// Create semaphore for concurrency control
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	var totalErrors int32
	var totalProcessed int32

	// Process packages in batches
	numBatches := (len(topPackages) + batchSize - 1) / batchSize
	log.Printf("📊 Processing %d packages in %d batches (batch size: %d, max concurrency: %d)",
		len(topPackages), numBatches, batchSize, maxConcurrency)

	for i := 0; i < len(topPackages); i += batchSize {
		end := min(i+batchSize, len(topPackages))
		batchNum := (i / batchSize) + 1

		batch := topPackages[i:end]
		wg.Add(1)

		go func(packageBatch []string, batchNumber int) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire semaphore
			defer func() { <-sem }() // Release semaphore

			err := UpdatePackagesBatch(db, packageBatch)
			if err != nil {
				log.Printf("⚠️  Batch %d/%d failed, falling back to individual processing: %v", batchNumber, numBatches, err)
				// Fall back to individual processing for this batch
				for _, pkg := range packageBatch {
					UpdatePackage(db, pkg)
				}
				atomic.AddInt32(&totalErrors, 1)
			}
			atomic.AddInt32(&totalProcessed, int32(len(packageBatch)))
		}(batch, batchNum)
	}

	wg.Wait()
	duration := time.Since(start)
	packagesPerSec := float64(len(topPackages)) / duration.Seconds()

	if totalErrors > 0 {
		log.Printf("⚠️  Completed JavaScript import with %d batch errors in %v (%.1f packages/sec)",
			totalErrors, duration, packagesPerSec)
	} else {
		log.Printf("✅ Successfully completed JavaScript batch import in %v (%.1f packages/sec)",
			duration, packagesPerSec)
	}

	return nil
}

func ImportTop10000(db *bun.DB, db_config *bun.DB) error {
	log.Println("Start importing JS")
	var wg sync.WaitGroup
	maxGoroutines := 50
	guard := make(chan struct{}, maxGoroutines)

	// Read top-packages.json file
	file, err := os.Open("data/npm-packages.json")
	if err != nil {
		log.Println("Error opening top-packages.json:", err)
		return err
	}
	defer file.Close()

	// Parse JSON data
	var topPackages []string
	err = json.NewDecoder(file).Decode(&topPackages)
	if err != nil {
		log.Println("Error decoding top-packages.json:", err)
		return err
	}

	// Configure progression bar
	bar := progressbar.Default(int64(len(topPackages)))

	for _, npmPackage := range topPackages {
		wg.Add(1)
		guard <- struct{}{}
		go func(wg *sync.WaitGroup, packageName string) {
			defer wg.Done()
			defer bar.Add(1)
			// Get package
			UpdatePackage(db, packageName)

			<-guard
		}(&wg, npmPackage)
	}
	wg.Wait()
	return nil
}

// Follow is a function that imports JavaScript packages into a graph database.
// It takes a collection, a graph, and a graphLicenses as input parameters.
// It returns an error if there is any issue during the import process.
func Follow(db *bun.DB, db_config *bun.DB) error {
	log.Println("Start importing JS")
	var wg sync.WaitGroup
	maxGoroutines := 50
	guard := make(chan struct{}, maxGoroutines)

	var npmPackages []knowledge.Package
	count, err := db.NewSelect().Column("name").Model(&npmPackages).Where("language = ?", "javascript").ScanAndCount(context.Background())
	if err != nil {
		panic(err)
	}

	// Configure progression bar
	bar := progressbar.Default(int64(count))

	for _, npmPackage := range npmPackages {
		wg.Add(1)
		guard <- struct{}{}
		go func(wg *sync.WaitGroup, packageName string) {
			defer wg.Done()
			defer bar.Add(1)
			// Get package
			UpdatePackage(db, packageName)

			<-guard
		}(&wg, npmPackage.Name)
	}
	wg.Wait()
	return nil
}

// UpdatePackage updates a package in the graph database with the given name.
// It downloads the package information, creates package and link information,
// adds licenses for each package and version, and updates the package and link
// information in the graph database.
//
// Parameters:
// - graph: The graph database to update the package in.
// - graphLicenses: The graph database to update the link licenses in.
// - name: The name of the package to update.
//
// Returns:
// - An error if any occurred during the update process, or nil if the update was successful.
func UpdatePackage(db *bun.DB, name string) error {
	var existingPackage knowledge.Package
	err := db.NewSelect().Model(&existingPackage).Where("name = ? AND language = ?", name, "javascript").Scan(context.Background())
	if err == nil {
		// Check if the package was updated in the last 4 hours
		if existingPackage.Time.After(time.Now().Add(-4 * time.Hour)) {
			// Skip package update if true
			return nil
		}
	}

	// Get package
	result, err := download(name)
	if err != nil {
		log.Println(err)
		return err
	}

	// Create package
	pack := tools.CreatePackageInfoNpm(result)

	err = pgsql.UpdatePackage(db, pack)
	if err != nil {
		log.Println("Error when updating package", err)
		return err
	}

	return nil
}

// UpdatePackagesBatch updates multiple JavaScript packages in a single optimized batch operation
func UpdatePackagesBatch(db *bun.DB, packageNames []string) error {
	if len(packageNames) == 0 {
		return nil
	}

	// Removed verbose per-batch logging to reduce noise

	// Download all packages concurrently
	type packageResult struct {
		name string
		pack knowledge.Package
		err  error
	}

	results := make(chan packageResult, len(packageNames))
	var downloadWg sync.WaitGroup
	sem := make(chan struct{}, 10) // Limit concurrent downloads

	for _, pkgName := range packageNames {
		downloadWg.Add(1)
		go func(name string) {
			defer downloadWg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Check if package was recently updated (cache check)
			var existingPackage knowledge.Package
			err := db.NewSelect().Model(&existingPackage).Where("name = ? AND language = ?", name, "javascript").Scan(context.Background())
			if err == nil {
				// Check if the package was updated in the last 4 hours
				if existingPackage.Time.After(time.Now().Add(-4 * time.Hour)) {
					results <- packageResult{name: name, pack: knowledge.Package{}, err: nil} // Skip
					return
				}
			}

			// Download package from NPM
			result, err := download(name)
			if err != nil {
				results <- packageResult{name: name, err: err}
				return
			}

			// Create package using the same tools as individual processing
			pack := tools.CreatePackageInfoNpm(result)
			results <- packageResult{name: name, pack: pack, err: nil}
		}(pkgName)
	}

	// Wait for all downloads to complete
	go func() {
		downloadWg.Wait()
		close(results)
	}()

	// Collect all packages for batch database operations
	var packagesToUpdate []knowledge.Package
	var versionsToInsert []knowledge.Version
	var versionsToUpdate []knowledge.Version

	for result := range results {
		if result.err != nil {
			log.Printf("Error downloading JavaScript package %s: %v", result.name, result.err)
			continue
		}

		if result.pack.Name == "" {
			continue // Skipped due to recent update
		}

		packagesToUpdate = append(packagesToUpdate, result.pack)
	}

	if len(packagesToUpdate) == 0 {
		return nil // Nothing to update
	}

	// Use database transaction for batch operations
	err := db.RunInTx(context.Background(), nil, func(ctx context.Context, tx bun.Tx) error {
		// Batch upsert packages using prepared statements
		for _, pack := range packagesToUpdate {
			var existingPackage knowledge.Package
			err := tx.NewSelect().Model(&existingPackage).Where("name = ? AND language = ?", pack.Name, pack.Language).Scan(ctx)
			if err != nil {
				// Insert new package
				_, err := tx.NewInsert().Model(&pack).Exec(ctx)
				if err != nil {
					return fmt.Errorf("failed to insert package %s: %w", pack.Name, err)
				}
			} else {
				// Update existing package
				pack.Id = existingPackage.Id // Preserve ID for updates
				_, err = tx.NewUpdate().Model(&pack).Where("id = ?", existingPackage.Id).Exec(ctx)
				if err != nil {
					return fmt.Errorf("failed to update package %s: %w", pack.Name, err)
				}
			}

			// Get updated package with ID for version processing
			err = tx.NewSelect().Model(&existingPackage).Relation("Versions").Where("name = ? AND language = ?", pack.Name, pack.Language).Scan(ctx)
			if err != nil {
				return fmt.Errorf("failed to fetch package %s for version processing: %w", pack.Name, err)
			}

			// Batch process versions
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
				return fmt.Errorf("failed to batch insert versions: %w", err)
			}
		}

		// Batch update existing versions
		for _, version := range versionsToUpdate {
			_, err := tx.NewUpdate().Model(&version).Where("package_id = ? and version = ?", version.PackageID, version.Version).Exec(ctx)
			if err != nil {
				return fmt.Errorf("failed to update version %s for package ID %d: %w", version.Version, version.PackageID, err)
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("batch database operation failed: %w", err)
	}

	// Reduced to single line summary for cleaner logs

	return nil
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
