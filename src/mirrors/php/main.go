package php

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
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
	"github.com/schollz/progressbar/v3"
	"github.com/uptrace/bun"
)

type List struct {
	PackageNames []string `json:"packageNames"`
}

// ImportList imports a list of PHP packages from Packagist
func ImportList(db *bun.DB, topPackages []string) error {
	log.Println("Start importing PHP packages from Packagist")
	var wg sync.WaitGroup
	maxGoroutines := 10
	guard := make(chan struct{}, maxGoroutines)

	// Configure progression bar
	bar := progressbar.Default(int64(len(topPackages)))

	for _, phpPackage := range topPackages {
		wg.Add(1)
		guard <- struct{}{}
		go func(wg *sync.WaitGroup, packageName string) {
			defer wg.Done()
			defer bar.Add(1)
			// Get package
			UpdatePackage(db, packageName)

			<-guard
		}(&wg, phpPackage)
	}
	wg.Wait()
	return nil
}

// ImportListWithBatching imports a list of PHP packages using batch processing for improved performance
func ImportListWithBatching(db *bun.DB, topPackages []string) error {
	if len(topPackages) == 0 {
		return nil
	}

	start := time.Now()
	log.Printf("🔄 Starting batch import of %d PHP packages from Packagist", len(topPackages))

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
		log.Printf("⚠️  Completed PHP import with %d batch errors in %v (%.1f packages/sec)",
			totalErrors, duration, packagesPerSec)
	} else {
		log.Printf("✅ Successfully completed PHP batch import in %v (%.1f packages/sec)",
			duration, packagesPerSec)
	}

	return nil
}

// ImportTopPackages imports top PHP packages from a predefined list
func ImportTopPackages(db *bun.DB, db_config *bun.DB) error {
	log.Println("Start importing top PHP packages")
	var wg sync.WaitGroup
	maxGoroutines := 50
	guard := make(chan struct{}, maxGoroutines)

	// Read top PHP packages file (if exists)
	file, err := os.Open("data/php-packages.json")
	if err != nil {
		// If file doesn't exist, use a default list of popular PHP packages
		log.Println("Using default PHP package list")
		topPackages := getDefaultTopPackages()
		return importPackageList(db, topPackages, &wg, guard)
	}
	defer file.Close()

	// Parse JSON data
	var topPackages []string
	err = json.NewDecoder(file).Decode(&topPackages)
	if err != nil {
		log.Println("Error decoding php-packages.json:", err)
		return err
	}

	return importPackageList(db, topPackages, &wg, guard)
}

// importPackageList helper function to import a list of packages
func importPackageList(db *bun.DB, packages []string, wg *sync.WaitGroup, guard chan struct{}) error {
	// Configure progression bar
	bar := progressbar.Default(int64(len(packages)))

	for _, phpPackage := range packages {
		wg.Add(1)
		guard <- struct{}{}
		go func(wg *sync.WaitGroup, packageName string) {
			defer wg.Done()
			defer bar.Add(1)
			// Get package
			UpdatePackage(db, packageName)

			<-guard
		}(wg, phpPackage)
	}
	wg.Wait()
	return nil
}

// Follow updates all PHP packages already in the database
func Follow(db *bun.DB, db_config *bun.DB) error {
	log.Println("Start following PHP packages")
	var wg sync.WaitGroup
	maxGoroutines := 50
	guard := make(chan struct{}, maxGoroutines)

	// Get all PHP packages from database
	var phpPackages []knowledge.Package
	count, err := db.NewSelect().
		Column("name").
		Model(&phpPackages).
		Where("language = ?", "php").
		ScanAndCount(context.Background())
	if err != nil {
		log.Printf("Error fetching PHP packages: %v", err)
		return err
	}

	// Configure progression bar
	bar := progressbar.Default(int64(count))

	for _, phpPackage := range phpPackages {
		wg.Add(1)
		guard <- struct{}{}
		go func(wg *sync.WaitGroup, packageName string) {
			defer wg.Done()
			defer bar.Add(1)
			// Get package
			UpdatePackage(db, packageName)

			<-guard
		}(&wg, phpPackage.Name)
	}
	wg.Wait()
	return nil
}

// UpdatePackagesBatch updates multiple PHP packages in a single optimized batch operation
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
		Where("name IN (?) AND language = ?", bun.In(packageNames), "php").
		Scan(ctx)
	if err != nil {
		log.Printf("Cache check query failed, downloading all: %v", err)
	}

	recentCutoff := time.Now().Add(-4 * time.Hour)
	skipSet := make(map[string]bool, len(cachedPackages))
	for _, p := range cachedPackages {
		if p.Time.After(recentCutoff) {
			skipSet[p.Name] = true
		}
	}

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

			result, err := downloadPackagist(name)
			if err != nil {
				results <- packageResult{name: name, err: err}
				return
			}

			pack := convertPackagistToKnowledge(result)
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
			log.Printf("Error downloading PHP package %s: %v", result.name, result.err)
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
			Where("name IN (?) AND language = ?", bun.In(names), "php").
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

		existingVersionSet := make(map[uuid.UUID]map[string]bool)
		for _, v := range existingVersions {
			if existingVersionSet[v.PackageID] == nil {
				existingVersionSet[v.PackageID] = make(map[string]bool)
			}
			existingVersionSet[v.PackageID][v.Version] = true
		}

		// Collect all versions for batch upsert
		var allVersions []knowledge.Version
		for _, pack := range packagesToUpdate {
			pkgId, ok := pkgIdMap[pack.Name]
			if !ok {
				continue
			}

			for _, version := range pack.Versions {
				if isPreviewVersion(version.Version) {
					continue
				}
				version.PackageID = pkgId
				allVersions = append(allVersions, version)
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

// UpdatePackage updates a PHP package in the database
func UpdatePackage(db *bun.DB, name string) error {
	// Check if package exists and was recently updated
	var existingPackage knowledge.Package
	err := db.NewSelect().Model(&existingPackage).Where("name = ? AND language = ?", name, "php").Scan(context.Background())
	if err == nil {
		// Check if the package was updated in the last 4 hours
		if existingPackage.Time.After(time.Now().Add(-4 * time.Hour)) {
			// Skip package update if true
			return nil
		}
	}

	// Download package from Packagist
	result, err := downloadPackagist(name)
	if err != nil {
		log.Printf("Error downloading PHP package %s: %v", name, err)
		return err
	}

	// Convert to internal package format
	pack := convertPackagistToKnowledge(result)

	// Update package in database
	err = pgsql.UpdatePackage(db, pack)
	if err != nil {
		log.Printf("Error updating PHP package %s in database: %v", name, err)
		return err
	}

	return nil
}

// convertPackagistToKnowledge converts Packagist package to knowledge DB format
func convertPackagistToKnowledge(packagist *PackagistPackage) knowledge.Package {
	pack := knowledge.Package{
		Name:        packagist.Package.Name,
		Language:    "php",
		Description: packagist.Package.Description,
		Homepage:    packagist.Package.Homepage,
		Keywords:    packagist.Package.Keywords,
		Time:        time.Now(),
	}

	// Find latest stable version
	var latestVersion string
	var latestTime time.Time

	for version, info := range packagist.Package.Versions {
		// Skip dev versions
		if strings.Contains(version, "dev") {
			continue
		}

		// Parse time
		versionTime, err := time.Parse(time.RFC3339, info.Time)
		if err != nil {
			continue
		}

		// Check if this is the latest
		if versionTime.After(latestTime) {
			latestTime = versionTime
			latestVersion = version
		}
	}

	pack.LatestVersion = latestVersion

	// Process versions
	pack.Versions = make([]knowledge.Version, 0, len(packagist.Package.Versions))
	for version, info := range packagist.Package.Versions {
		// Convert flexible fields to consistent format
		var licenses []string
		switch lic := info.License.(type) {
		case string:
			licenses = []string{lic}
		case []interface{}:
			for _, l := range lic {
				if str, ok := l.(string); ok {
					licenses = append(licenses, str)
				}
			}
		case []string:
			licenses = lic
		}

		v := knowledge.Version{
			Version: version,
			Extra: map[string]interface{}{
				"type":     info.Type,
				"time":     info.Time,
				"source":   info.Source,
				"dist":     info.Dist,
				"license":  licenses,
				"authors":  info.Authors,
				"autoload": info.Autoload,
				"support":  info.Support,
				"funding":  NormalizeFunding(info.Funding),
				"extra":    info.Extra,
				"suggest":  NormalizeDependencies(info.Suggest),
				"provide":  NormalizeDependencies(info.Provide),
				"replace":  NormalizeDependencies(info.Replace),
				"conflict": NormalizeDependencies(info.Conflict),
			},
		}

		// Convert dependencies - normalize to handle flexible types
		v.Dependencies = NormalizeDependencies(info.Require)
		v.DevDependencies = NormalizeDependencies(info.RequireDev)

		pack.Versions = append(pack.Versions, v)
	}

	// Extract source information
	if len(pack.Versions) > 0 {
		// Use latest version's source
		for _, info := range packagist.Package.Versions {
			if info.Version == latestVersion {
				pack.Source = knowledge.Source{
					Type: info.Source.Type,
					Url:  info.Source.Url,
				}
				break
			}
		}
	}

	// Extract license information
	if len(pack.Versions) > 0 {
		for _, info := range packagist.Package.Versions {
			if info.Version == latestVersion {
				// Handle flexible license type
				var licenses []string
				switch lic := info.License.(type) {
				case string:
					licenses = []string{lic}
				case []interface{}:
					for _, l := range lic {
						if str, ok := l.(string); ok {
							licenses = append(licenses, str)
						}
					}
				case []string:
					licenses = lic
				}

				if len(licenses) > 0 {
					pack.License = strings.Join(licenses, ", ")
					pack.Licenses = make([]knowledge.LicenseNpm, len(licenses))
					for i, lic := range licenses {
						pack.Licenses[i] = knowledge.LicenseNpm{
							Type: lic,
							Url:  "",
						}
					}
					break
				}
			}
		}
	}

	return pack
}

// getDefaultTopPackages returns a list of popular PHP packages
func getDefaultTopPackages() []string {
	return []string{
		"symfony/console",
		"symfony/http-foundation",
		"symfony/http-kernel",
		"laravel/framework",
		"guzzlehttp/guzzle",
		"monolog/monolog",
		"phpunit/phpunit",
		"doctrine/orm",
		"slim/slim",
		"twig/twig",
		"phpmailer/phpmailer",
		"symfony/symfony",
		"nesbot/carbon",
		"vlucas/phpdotenv",
		"ramsey/uuid",
		"league/flysystem",
		"psr/log",
		"psr/container",
		"psr/http-message",
		"nikic/php-parser",
		"composer/composer",
		"firebase/php-jwt",
		"intervention/image",
		"spatie/laravel-permission",
		"barryvdh/laravel-debugbar",
	}
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
