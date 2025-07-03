package pgsql

import (
	"context"
	"fmt"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

func UpdateNvd(db *bun.DB, nvd []knowledge.NVDItem) error {
	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		} else if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	ctx := context.Background()
	for _, vuln := range nvd {
		exists, err := tx.NewSelect().Model(&vuln).Where("nvd_id = ?", vuln.NVDId).Exists(ctx)
		if err != nil {
			return fmt.Errorf("failed to check existence for NVD item %v: %w", vuln.NVDId, err)
		}

		if !exists {
			_, err = tx.NewInsert().Model(&vuln).Exec(ctx)
			if err != nil {
				return fmt.Errorf("failed to insert NVD item %v: %w", vuln.NVDId, err)
			}
		} else {
			_, err = tx.NewUpdate().Model(&vuln).WherePK().Exec(ctx)
			if err != nil {
				return fmt.Errorf("failed to update NVD item %v: %w", vuln.NVDId, err)
			}
		}
	}

	return nil
}
