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

	// Batch insert and update
	var newItems []knowledge.NVDItem
	var existingItems []knowledge.NVDItem

	for _, vuln := range nvd {
		exists, err := tx.NewSelect().Model(&vuln).Where("nvd_id = ?", vuln.NVDId).Exists(ctx)
		if err != nil {
			return fmt.Errorf("failed to check existence for NVD item %v: %w", vuln.NVDId, err)
		}

		if !exists {
			newItems = append(newItems, vuln)
		} else {
			existingItems = append(existingItems, vuln)
		}
	}

	if len(newItems) > 0 {
		_, err = tx.NewInsert().Model(&newItems).Exec(ctx)
		if err != nil {
			return fmt.Errorf("failed to batch insert NVD items: %w", err)
		}
	}

	if len(existingItems) > 0 {
		_, err = tx.NewUpdate().Model(&existingItems).WherePK().Exec(ctx)
		if err != nil {
			return fmt.Errorf("failed to batch update NVD items: %w", err)
		}
	}

	return nil
}
