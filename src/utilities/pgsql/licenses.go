package pgsql

import (
	"context"
	"fmt"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

func UpdateLicenses(db *bun.DB, licenses []knowledge.License) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	// A failure rolls back every license written so far.
	defer tx.Rollback()

	for _, license := range licenses {
		exists, err := tx.NewSelect().Model(&license).Where("\"licenseId\" = ?", license.LicenseID).Exists(context.Background())
		if err != nil {
			return fmt.Errorf("failed to check existence for license %v: %w", license.LicenseID, err)
		}

		if exists {
			_, err = tx.NewUpdate().Model(&license).Where("\"licenseId\" = ?", license.LicenseID).Exec(context.Background())
			if err != nil {
				return fmt.Errorf("failed to update license %v: %w", license.LicenseID, err)
			}
		} else {
			_, err = tx.NewInsert().Model(&license).Exec(context.Background())
			if err != nil {
				return fmt.Errorf("failed to insert license %v: %w", license.LicenseID, err)
			}
		}
	}

	return tx.Commit()
}
