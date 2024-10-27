package pgsql

import (
	"context"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

func UpdateLicenses(db *bun.DB, licenses []knowledge.License) error {

	for _, license := range licenses {

		exists, err := db.NewSelect().Model(&license).Where("\"licenseId\" = ?", license.LicenseID).Exists(context.Background())
		if err != nil {
			return err
		}

		if exists {
			_, err = db.NewUpdate().Model(&license).Where("\"licenseId\" = ?", license.LicenseID).Exec(context.Background())
			if err != nil {
				return err
			}
		} else {
			_, err = db.NewInsert().Model(&license).Exec(context.Background())
			if err != nil {
				return err
			}
		}
	}

	return nil
}
