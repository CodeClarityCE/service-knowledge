package pgsql

import (
	"context"
	"database/sql"
	"fmt"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// UpdateOsv updates or inserts an OSV document using an efficient upsert operation.
// This replaces the inefficient check-then-act pattern with a single atomic operation.
func UpdateOsv(db *bun.DB, osv knowledge.OSVItem) error {
	ctx := context.Background()

	// Use upsert (INSERT ... ON CONFLICT) for better performance and atomicity
	_, err := db.NewInsert().
		Model(&osv).
		On("CONFLICT (osv_id) DO UPDATE SET schema_version = EXCLUDED.schema_version, vlai_score = EXCLUDED.vlai_score, vlai_confidence = EXCLUDED.vlai_confidence, modified = EXCLUDED.modified, published = EXCLUDED.published, withdrawn = EXCLUDED.withdrawn, aliases = EXCLUDED.aliases, related = EXCLUDED.related, summary = EXCLUDED.summary, details = EXCLUDED.details, severity = EXCLUDED.severity, affected = EXCLUDED.affected, \"references\" = EXCLUDED.\"references\", credits = EXCLUDED.credits, database_specific = EXCLUDED.database_specific, cwes = EXCLUDED.cwes, cve = EXCLUDED.cve").
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to upsert OSV record with ID %s: %w", osv.OSVId, err)
	}

	return nil
}

// BatchUpdateOsv performs efficient batch upsert operations for multiple OSV records.
// This is significantly more efficient than individual updates when processing many records.
func BatchUpdateOsv(db *bun.DB, osvItems []knowledge.OSVItem) error {
	if len(osvItems) == 0 {
		return nil
	}

	ctx := context.Background()

	// Start a transaction for better performance and consistency
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for batch OSV update: %w", err)
	}
	defer tx.Rollback()

	// Use batch insert with ON CONFLICT for maximum efficiency
	_, err = tx.NewInsert().
		Model(&osvItems).
		On("CONFLICT (osv_id) DO UPDATE SET schema_version = EXCLUDED.schema_version, vlai_score = EXCLUDED.vlai_score, vlai_confidence = EXCLUDED.vlai_confidence, modified = EXCLUDED.modified, published = EXCLUDED.published, withdrawn = EXCLUDED.withdrawn, aliases = EXCLUDED.aliases, related = EXCLUDED.related, summary = EXCLUDED.summary, details = EXCLUDED.details, severity = EXCLUDED.severity, affected = EXCLUDED.affected, \"references\" = EXCLUDED.\"references\", credits = EXCLUDED.credits, database_specific = EXCLUDED.database_specific, cwes = EXCLUDED.cwes, cve = EXCLUDED.cve").
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to batch upsert %d OSV records: %w", len(osvItems), err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction for batch OSV update: %w", err)
	}

	return nil
}

// GetOsvByID retrieves an OSV record by its OSV ID.
func GetOsvByID(db *bun.DB, osvId string) (*knowledge.OSVItem, error) {
	ctx := context.Background()

	osv := &knowledge.OSVItem{}
	err := db.NewSelect().
		Model(osv).
		Where("osv_id = ?", osvId).
		Scan(ctx)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, err
		}
		return nil, fmt.Errorf("failed to retrieve OSV record with ID %s: %w", osvId, err)
	}

	return osv, nil
}
