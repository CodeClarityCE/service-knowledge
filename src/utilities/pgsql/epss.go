package pgsql

import (
	"context"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// UpdateCWE updates the CWE (Common Weakness Enumeration) entries in the graph database.
// It takes a graph driver and a slice of CWEEntry structs as input.
// For each CWEEntry in the slice, it tries to update the corresponding document in the "CWE" vertex collection.
// If the document exists and is successfully updated, it generates a changelog and creates a new document in the "REVISIONS" vertex collection.
// If the document doesn't exist, it creates a new document in the "CWE" vertex collection.
// Returns an error if any operation fails.
func UpdateEPSS(db *bun.DB, epssScores []knowledge.EPSS) error {
	ctx := context.Background()

	toInsert := []knowledge.EPSS{}
	toUpdate := []knowledge.EPSS{}

	// Create a map to track existing CVEs in the database
	existingCVEs := make(map[string]bool)

	// Fetch all existing CVEs in one query
	var dbCVEs []string
	err := db.NewSelect().Model((*knowledge.EPSS)(nil)).Column("cve").Scan(ctx, &dbCVEs)
	if err != nil {
		return err
	}

	// Populate the map with existing CVEs
	for _, cve := range dbCVEs {
		existingCVEs[cve] = true
	}

	// Separate records into insert and update lists
	for _, epss := range epssScores {
		if existingCVEs[epss.CVE] {
			toUpdate = append(toUpdate, epss)
		} else {
			toInsert = append(toInsert, epss)
		}
	}

	// Bulk insert
	if len(toInsert) > 0 {
		_, err := db.NewInsert().Model(&toInsert).Exec(ctx)
		if err != nil {
			return err
		}
	}

	if len(toUpdate) > 0 {
		// Bulk update
		_, err := db.NewUpdate().
			Model(&toUpdate).
			Where("cve = _data.cve").
			Bulk().
			Exec(ctx)
		if err != nil {
			return err
		}
	}

	return nil
}
