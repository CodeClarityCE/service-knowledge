// Package osv_asof rebuilds the OSV vulnerabilities from a dated checkout of
// the github/advisory-database repository, so the knowledge database can be
// materialized in the state it would have had at an arbitrary past date.
// Ecosystem scope, the JSON -> OSVItem transform and the batch storage path
// are shared with the live mirror (src/mirrors/osv), so the only difference
// to a regular import is which advisories exist in the checkout.
package osv_asof

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/mirrors/osv"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// batchSize matches the live mirror's batch size for OSV inserts.
const batchSize = 100

// loadStats counts how the advisories of a checkout were handled.
type loadStats struct {
	kept             int
	skippedEcosystem int
	skippedFuture    int
	skippedInvalid   int
}

// Update replaces the OSV rows in the knowledge database with the advisories
// found in the github-reviewed tree of an advisory-database checkout. The
// checkout is expected to already be at the dated commit; asof is used for
// logging and as a defensive filter that skips advisories published after the
// asof day (a correctly dated checkout makes this a no-op). checkoutDate (the
// commit date of the checkout) is stamped as osv_last on the config database.
func Update(db *bun.DB, configDB *bun.DB, checkoutDir string, asof time.Time, checkoutDate time.Time) error {
	dir := filepath.Join(checkoutDir, "advisories", "github-reviewed")
	log.Printf("Start importing OSV vulnerabilities as of %s from %s", asof.Format("2006-01-02"), dir)

	items, stats, err := loadAdvisories(dir, asof)
	if err != nil {
		return fmt.Errorf("failed to load advisories from %s: %w", dir, err)
	}
	log.Printf("Loaded %d advisories (%d out-of-scope ecosystem, %d published after as-of date, %d invalid)",
		stats.kept, stats.skippedEcosystem, stats.skippedFuture, stats.skippedInvalid)

	if err := replaceOsvRows(db, items); err != nil {
		return err
	}

	return osv.SetLastOSVSync(configDB, checkoutDate)
}

// loadAdvisories walks dir for advisory JSON files, transforms them with the
// live mirror's ParseAdvisory, and keeps only advisories in the mirror's
// ecosystem scope that were not published after the asof day.
func loadAdvisories(dir string, asof time.Time) ([]knowledge.OSVItem, loadStats, error) {
	var items []knowledge.OSVItem
	var stats loadStats

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		item, err := osv.ParseAdvisory(data)
		if err != nil {
			log.Printf("Error unmarshaling JSON from %s: %v", path, err)
			stats.skippedInvalid++
			return nil
		}

		if !inScope(item) {
			stats.skippedEcosystem++
			return nil
		}
		if publishedAfter(item, asof) {
			log.Printf("Skipping %s: published %s postdates as-of date %s", item.OSVId, item.Published, asof.Format("2006-01-02"))
			stats.skippedFuture++
			return nil
		}

		items = append(items, item)
		stats.kept++
		return nil
	})
	if err != nil {
		return nil, stats, err
	}

	return items, stats, nil
}

// inScope reports whether the advisory affects at least one package in the
// live mirror's ecosystem scope (osv.ImportedEcosystems). This mirrors the
// GCS import, where an advisory is only seen if it appears in one of the
// per-ecosystem zip files.
func inScope(item knowledge.OSVItem) bool {
	for _, affected := range item.Affected {
		if slices.Contains(osv.ImportedEcosystems, affected.Package.Ecosystem) {
			return true
		}
	}
	return false
}

// publishedAfter reports whether the advisory's published timestamp falls
// after the end of the asof day (the whole asof day is in range). Advisories
// without a parseable published timestamp are kept, like in the live mirror.
func publishedAfter(item knowledge.OSVItem, asof time.Time) bool {
	if item.Published == "" {
		return false
	}
	published, err := time.Parse(time.RFC3339, item.Published)
	if err != nil {
		log.Printf("Keeping %s: cannot parse published timestamp %q: %v", item.OSVId, item.Published, err)
		return false
	}
	cutoff := asof.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	return !published.Before(cutoff)
}

// scopeCondition builds the SQL predicate (and its args) selecting the OSV
// rows the live mirror maintains: rows whose affected packages contain one of
// the mirror's ecosystems (JSONB containment, same GIN-indexable @> pattern
// used elsewhere). This is exactly the set the live mirror can have imported —
// the osv table is only ever written with advisories from those per-ecosystem
// zip files — while rows from any other source or ecosystem are left alone.
func scopeCondition() (string, []any, error) {
	conditions := make([]string, len(osv.ImportedEcosystems))
	args := make([]any, len(osv.ImportedEcosystems))
	for i, ecosystem := range osv.ImportedEcosystems {
		pattern, err := json.Marshal([]map[string]any{{"package": map[string]any{"ecosystem": ecosystem}}})
		if err != nil {
			return "", nil, fmt.Errorf("failed to marshal ecosystem pattern for %s: %w", ecosystem, err)
		}
		conditions[i] = "affected @> ?::jsonb"
		args[i] = string(pattern)
	}
	return strings.Join(conditions, " OR "), args, nil
}

// replaceOsvRows deletes the OSV rows the live mirror maintains and re-inserts
// the dated set through the mirror's own batch path (osv.InsertBatch), which
// also rebuilds the package_vulnerability links. Deletion covers the
// scopeCondition set plus its package_vulnerability links; both deletes run
// in one transaction, the inserts reuse the mirror's per-batch transactions.
func replaceOsvRows(db *bun.DB, items []knowledge.OSVItem) error {
	ctx := context.Background()

	scope, args, err := scopeCondition()
	if err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for OSV as-of delete: %w", err)
	}
	defer tx.Rollback()

	// Delete the package_vulnerability links of the in-scope OSV rows first
	// (they reference osv.id).
	_, err = tx.NewDelete().
		Model((*knowledge.PackageVulnerability)(nil)).
		Where("osv_id IN (SELECT id FROM osv WHERE "+scope+")", args...).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete OSV package vulnerability links: %w", err)
	}

	deleted, err := tx.NewDelete().
		Model((*knowledge.OSVItem)(nil)).
		Where(scope, args...).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete in-scope OSV rows: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit OSV as-of delete: %w", err)
	}

	if rows, err := deleted.RowsAffected(); err == nil {
		log.Printf("Deleted %d in-scope OSV rows, inserting %d dated advisories", rows, len(items))
	}

	for start := 0; start < len(items); start += batchSize {
		end := min(start+batchSize, len(items))
		if err := osv.InsertBatch(db, items[start:end], "github-reviewed"); err != nil {
			return fmt.Errorf("failed to insert as-of OSV batch: %w", err)
		}
	}

	return nil
}
