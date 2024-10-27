// Package psql provides utility functions for working with Postgre in the context of a knowledge database.
package pgsql

import (
	"context"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
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
	err := db.NewSelect().Model(&existingPackage).Where("name = ?", pack.Name).Scan(context.Background())
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

	err = db.NewSelect().Model(&existingPackage).Relation("Versions").Where("name = ?", pack.Name).Scan(context.Background())
	if err != nil {
		return err
	}

	// Insert new versions
	for _, version := range pack.Versions {
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
		} else { // If the version exists, update it
			_, err := db.NewUpdate().Model(&version).Where("'packageId' = ? and version = ?", existingPackage.Id, version.Version).Exec(context.Background())
			if err != nil {
				return err
			}
		}
	}

	return nil
}
