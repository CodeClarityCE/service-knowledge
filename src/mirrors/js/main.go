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
	"github.com/google/uuid"
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

	ctx := context.Background()

	// Phase 1: Batch cache check -- single query for all packages
	var cachedPackages []knowledge.Package
	err := db.NewSelect().
		Model(&cachedPackages).
		Column("name", "time").
		Where("name IN (?) AND language = ?", bun.In(packageNames), "javascript").
		Scan(ctx)
	if err != nil {
		// Not fatal -- proceed with all packages if cache check fails
		log.Printf("Cache check query failed, downloading all: %v", err)
	}

	recentCutoff := time.Now().Add(-4 * time.Hour)
	skipSet := make(map[string]bool, len(cachedPackages))
	for _, p := range cachedPackages {
		if p.Time.After(recentCutoff) {
			skipSet[p.Name] = true
		}
	}

	// Filter to packages that need downloading
	var toDownload []string
	for _, name := range packageNames {
		if !skipSet[name] {
			toDownload = append(toDownload, name)
		}
	}

	if len(toDownload) == 0 {
		return nil
	}

	// Phase 2: Concurrent HTTP downloads
	type packageResult struct {
		name string
		pack knowledge.Package
		err  error
	}

	results := make(chan packageResult, len(toDownload))
	var downloadWg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, pkgName := range toDownload {
		downloadWg.Add(1)
		go func(name string) {
			defer downloadWg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result, err := download(name)
			if err != nil {
				results <- packageResult{name: name, err: err}
				return
			}

			pack := tools.CreatePackageInfoNpm(result)
			results <- packageResult{name: name, pack: pack, err: nil}
		}(pkgName)
	}

	go func() {
		downloadWg.Wait()
		close(results)
	}()

	var packagesToUpdate []knowledge.Package
	for result := range results {
		if result.err != nil {
			log.Printf("Error downloading JavaScript package %s: %v", result.name, result.err)
			continue
		}
		if result.pack.Name != "" {
			packagesToUpdate = append(packagesToUpdate, result.pack)
		}
	}

	if len(packagesToUpdate) == 0 {
		return nil
	}

	// Phase 3-5: Database transaction with batch upserts
	err = db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		// Phase 3: Batch upsert all packages using ON CONFLICT
		for i := range packagesToUpdate {
			_, err := tx.NewInsert().
				Model(&packagesToUpdate[i]).
				On("CONFLICT (name, language) DO UPDATE").
				Set("description = EXCLUDED.description").
				Set("homepage = EXCLUDED.homepage").
				Set("latest_version = EXCLUDED.latest_version").
				Set("\"time\" = EXCLUDED.\"time\"").
				Set("keywords = EXCLUDED.keywords").
				Set("source = EXCLUDED.source").
				Set("license = EXCLUDED.license").
				Set("licenses = EXCLUDED.licenses").
				Set("extra = EXCLUDED.extra").
				Exec(ctx)
			if err != nil {
				return fmt.Errorf("failed to upsert package %s: %w", packagesToUpdate[i].Name, err)
			}
		}

		// Batch fetch all package IDs
		names := make([]string, len(packagesToUpdate))
		for i, p := range packagesToUpdate {
			names[i] = p.Name
		}

		var pkgsWithIds []knowledge.Package
		err := tx.NewSelect().
			Model(&pkgsWithIds).
			Column("id", "name").
			Where("name IN (?) AND language = ?", bun.In(names), "javascript").
			Scan(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch package IDs: %w", err)
		}

		pkgIdMap := make(map[string]uuid.UUID, len(pkgsWithIds))
		packageIDs := make([]uuid.UUID, 0, len(pkgsWithIds))
		for _, p := range pkgsWithIds {
			pkgIdMap[p.Name] = p.Id
			packageIDs = append(packageIDs, p.Id)
		}

		// Phase 4: Batch load all existing versions
		var existingVersions []knowledge.Version
		if len(packageIDs) > 0 {
			err = tx.NewSelect().
				Model(&existingVersions).
				Where("package_id IN (?)", bun.In(packageIDs)).
				Scan(ctx)
			if err != nil {
				return fmt.Errorf("failed to batch load versions: %w", err)
			}
		}

		// Build O(1) lookup map: packageID -> versionString -> true
		existingVersionSet := make(map[uuid.UUID]map[string]bool)
		for _, v := range existingVersions {
			if existingVersionSet[v.PackageID] == nil {
				existingVersionSet[v.PackageID] = make(map[string]bool)
			}
			existingVersionSet[v.PackageID][v.Version] = true
		}

		// Classify versions as new or existing
		var allVersions []knowledge.Version
		for _, pack := range packagesToUpdate {
			pkgId, ok := pkgIdMap[pack.Name]
			if !ok {
				continue
			}
			existingVers := existingVersionSet[pkgId]

			for _, version := range pack.Versions {
				if isPreviewVersion(version.Version) {
					continue
				}
				version.PackageID = pkgId
				allVersions = append(allVersions, version)
				// Track new versions for potential notifications
				if existingVers == nil || !existingVers[version.Version] {
					// This is a new version (will be inserted by upsert)
					_ = version // tracked implicitly in allVersions
				}
			}
		}

		// Phase 5: Batch upsert all versions using ON CONFLICT
		if len(allVersions) > 0 {
			const chunkSize = 500
			for i := 0; i < len(allVersions); i += chunkSize {
				end := min(i+chunkSize, len(allVersions))
				chunk := allVersions[i:end]
				_, err := tx.NewInsert().
					Model(&chunk).
					On("CONFLICT (package_id, version) DO UPDATE").
					Set("dependencies = EXCLUDED.dependencies").
					Set("dev_dependencies = EXCLUDED.dev_dependencies").
					Set("extra = EXCLUDED.extra").
					Set("updated_at = NOW()").
					Exec(ctx)
				if err != nil {
					return fmt.Errorf("failed to batch upsert versions: %w", err)
				}
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("batch database operation failed: %w", err)
	}

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
