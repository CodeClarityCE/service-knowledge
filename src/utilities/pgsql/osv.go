package pgsql

import (
	"context"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// UpdateOsv updates the OSV (Open Source Vulnerabilities) document in the graph database.
// It first tries to update the existing document with the provided OSV data.
// If the document doesn't exist, it creates a new document with the OSV data.
// If the update is successful and there are changes in the OSV data, it generates a changelog and creates a new revision document.
// The function returns an error if any operation fails.
func UpdateOsv(db *bun.DB, osv knowledge.OSVItem) error {

	ctx := context.Background()
	exists, err := db.NewSelect().Model(&osv).Where("osv_id = ?", osv.OSVId).Exists(ctx)
	if err != nil {
		panic(err)
	}

	if !exists {
		_, err = db.NewInsert().Model(&osv).Exec(context.Background())
		if err != nil {
			return err
		}
		return nil
	}

	_, err = db.NewUpdate().Model(&osv).WherePK().Exec(context.Background())
	if err != nil {
		return err
	}

	return nil
}
