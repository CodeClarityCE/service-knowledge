package pgsql

import (
	"context"
	"fmt"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// kevChunkSize bounds one upsert statement.
const kevChunkSize = 1000

// UpdateKEV upserts catalog entries on cve in one transaction.
func UpdateKEV(db *bun.DB, entries []knowledge.KEV) error {
	if len(entries) == 0 {
		return nil
	}
	ctx := context.Background()
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		for start := 0; start < len(entries); start += kevChunkSize {
			chunk := entries[start:min(start+kevChunkSize, len(entries))]
			_, err := tx.NewInsert().
				Model(&chunk).
				ExcludeColumn("id").
				On(`CONFLICT (cve) DO UPDATE SET vendor_project = EXCLUDED.vendor_project, product = EXCLUDED.product,
					vulnerability_name = EXCLUDED.vulnerability_name, date_added = EXCLUDED.date_added,
					due_date = EXCLUDED.due_date, short_description = EXCLUDED.short_description,
					required_action = EXCLUDED.required_action, notes = EXCLUDED.notes,
					known_ransomware_use = EXCLUDED.known_ransomware_use, cwes = EXCLUDED.cwes`).
				Exec(ctx)
			if err != nil {
				return fmt.Errorf("upsert %d KEV entries: %w", len(chunk), err)
			}
		}
		return nil
	})
}

// ReconcileKEV deletes entries that a complete KEV catalog no longer lists.
func ReconcileKEV(db *bun.DB, snapshotCVEs []string) error {
	return reconcileSnapshotTable(db, knowledge.SourceKEV, "kev", "cve", snapshotCVEs)
}
