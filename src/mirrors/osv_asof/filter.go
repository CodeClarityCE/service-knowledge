package osv_asof

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/mirrors/osv"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// deleteChunkSize bounds the id lists passed to a single DELETE ... IN (...).
const deleteChunkSize = 10000

// Filter removes the in-scope OSV advisories whose published timestamp
// postdates the asof day from the live knowledge database, and stamps
// osv_last with asof. Unlike Update, which rebuilds advisories from a dated
// checkout, Filter is a membership-only approximation: advisories published
// on or before asof survive with their CURRENT content (affected ranges,
// severity, aliases as of the base state), and advisories that were live at
// asof but have since been withdrawn or deleted are not resurrected. The
// published-timestamp semantics (whole asof day in range, unparseable or
// empty timestamps kept) are shared with Update via publishedAfter.
func Filter(db *bun.DB, configDB *bun.DB, asof time.Time) error {
	ctx := context.Background()

	scope, args, err := scopeCondition()
	if err != nil {
		return err
	}

	var rows []knowledge.OSVItem
	err = db.NewSelect().
		Model(&rows).
		Column("id", "osv_id", "published").
		Where(scope, args...).
		Scan(ctx)
	if err != nil {
		return fmt.Errorf("failed to load in-scope OSV rows for filtering: %w", err)
	}

	drop := idsPublishedAfter(rows, asof)
	log.Printf("Filtering OSV as of %s: %d in-scope advisories, %d published after cutoff",
		asof.Format("2006-01-02"), len(rows), len(drop))

	if len(drop) > 0 {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to begin transaction for OSV filter delete: %w", err)
		}
		defer tx.Rollback()

		for start := 0; start < len(drop); start += deleteChunkSize {
			end := min(start+deleteChunkSize, len(drop))
			chunk := drop[start:end]

			// The package_vulnerability links reference osv.id, so they go first.
			_, err = tx.NewDelete().
				Model((*knowledge.PackageVulnerability)(nil)).
				Where("osv_id IN (?)", bun.In(chunk)).
				Exec(ctx)
			if err != nil {
				return fmt.Errorf("failed to delete package vulnerability links of filtered OSV rows: %w", err)
			}

			_, err = tx.NewDelete().
				Model((*knowledge.OSVItem)(nil)).
				Where("id IN (?)", bun.In(chunk)).
				Exec(ctx)
			if err != nil {
				return fmt.Errorf("failed to delete filtered OSV rows: %w", err)
			}
		}

		if err = tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit OSV filter delete: %w", err)
		}
	}

	return osv.SetLastOSVSync(configDB, asof)
}

// idsPublishedAfter returns the ids of the rows whose published timestamp
// falls after the end of the asof day, in input order.
func idsPublishedAfter(rows []knowledge.OSVItem, asof time.Time) []uuid.UUID {
	var ids []uuid.UUID
	for i := range rows {
		if publishedAfter(rows[i], asof) {
			ids = append(ids, rows[i].Id)
		}
	}
	return ids
}
