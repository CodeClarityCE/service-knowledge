package php

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
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

	// Get all PHP packages from database (those with vendor/ in name)
	var phpPackages []knowledge.Package
	count, err := db.NewSelect().
		Column("name").
		Model(&phpPackages).
		Where("name LIKE ?", "%/%"). // PHP packages have vendor/name format
		ScanAndCount(context.Background())
	if err != nil {
		log.Printf("Error fetching PHP packages: %v", err)
		return err
	}

	// Configure progression bar
	bar := progressbar.Default(int64(count))

	for _, phpPackage := range phpPackages {
		// Only process PHP packages (contain vendor/)
		if !strings.Contains(phpPackage.Name, "/") {
			bar.Add(1)
			continue
		}

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

// UpdatePackage updates a PHP package in the database
func UpdatePackage(db *bun.DB, name string) error {
	// Check if package exists and was recently updated
	var existingPackage knowledge.Package
	err := db.NewSelect().Model(&existingPackage).Where("name = ?", name).Scan(context.Background())
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
		v := knowledge.Version{
			Version: version,
			Extra: map[string]interface{}{
				"type":            info.Type,
				"time":            info.Time,
				"source":          info.Source,
				"dist":            info.Dist,
				"license":         info.License,
				"authors":         info.Authors,
				"autoload":        info.Autoload,
				"support":         info.Support,
				"funding":         info.Funding,
			},
		}
		
		// Convert dependencies
		if len(info.Require) > 0 {
			v.Dependencies = info.Require
		}
		if len(info.RequireDev) > 0 {
			v.DevDependencies = info.RequireDev
		}
		
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
			if info.Version == latestVersion && len(info.License) > 0 {
				pack.License = strings.Join(info.License, ", ")
				pack.Licenses = make([]knowledge.LicenseNpm, len(info.License))
				for i, lic := range info.License {
					pack.Licenses[i] = knowledge.LicenseNpm{
						Type: lic,
						Url:  "",
					}
				}
				break
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
