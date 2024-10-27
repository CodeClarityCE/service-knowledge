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
func UpdateCWE(db *bun.DB, cwes []knowledge.CWEEntry) error {
	ctx := context.Background()

	to_insert := []knowledge.CWEEntry{}
	to_update := []knowledge.CWEEntry{}

	// Check if the CWE already exists in the database
	// If it does, add it to the update list
	// If it doesn't, add it to the insert list
	for _, cwe_element := range cwes {
		exists, err := db.NewSelect().Model(&cwe_element).Where("cwe_id = ?", cwe_element.CWEId).Exists(ctx)
		if err != nil {
			return err
		}
		if exists {
			to_update = append(to_update, cwe_element)
		} else {
			to_insert = append(to_insert, cwe_element)
		}
	}

	// Bulk insert
	if len(to_insert) > 0 {
		_, err := db.NewInsert().Model(&to_insert).Exec(ctx)
		if err != nil {
			panic(err)
		}
	}

	if len(to_update) > 0 {
		// Bulk update
		_, err := db.NewUpdate().
			Model(&to_update).
			Where("c.cwe_id = _data.cwe_id").
			Bulk().
			Exec(ctx)
		if err != nil {
			panic(err)
		}

	}

	return nil
}
