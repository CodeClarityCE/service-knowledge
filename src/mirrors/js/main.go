// Package js contains the functions to update the JS mirror
package js

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"sync"
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
	count, err := db.NewSelect().Column("name").Model(&npmPackages).ScanAndCount(context.Background())
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
	err := db.NewSelect().Model(&existingPackage).Where("name = ?", name).Scan(context.Background())
	if err == nil {
		// Check if the package was updated in the last 12 hours
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
