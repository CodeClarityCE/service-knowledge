// Package validation checks the knowledge database after an update.
//
// It cannot undo a bad update, because updates are applied in place. A failing
// source keeps its last validated counts and raises an alert.
package validation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// Names of the checks a finding can come from.
const (
	CheckRowCount       = "row_count"
	CheckMaliciousCount = "malicious_count"
	CheckFreshness      = "freshness"
	CheckIntegrity      = "referential_integrity"
)

// maxDropPercent is the largest row-count drop a source may show between validations.
const maxDropPercent = 5

// Finding is one failed check for one source.
type Finding struct {
	Source  string
	Check   string
	Message string
}

// Report lists everything a validation run found.
type Report struct {
	Findings []Finding
}

// Failed reports whether any check failed.
func (r Report) Failed() bool {
	return len(r.Findings) > 0
}

// sources lists every knowledge source validation covers.
var sources = []string{
	knowledge.SourceCWE, knowledge.SourceEPSS, knowledge.SourceFriendsOfPHP, knowledge.SourceGCVE,
	knowledge.SourceLicenses, knowledge.SourceNVD, knowledge.SourceOSV,
}

// staleAfter is how old each source's watermark may be. Keep these equal to the
// API knowledge status endpoint and the Grafana alert.
var staleAfter = map[string]time.Duration{
	knowledge.SourceOSV:          24 * time.Hour,
	knowledge.SourceEPSS:         24 * time.Hour,
	knowledge.SourceNVD:          48 * time.Hour,
	knowledge.SourceGCVE:         48 * time.Hour,
	knowledge.SourceCWE:          7 * 24 * time.Hour,
	knowledge.SourceLicenses:     7 * 24 * time.Hour,
	knowledge.SourceFriendsOfPHP: 7 * 24 * time.Hour,
}

// linkColumns maps the advisory sources to their column in package_vulnerability.
var linkColumns = map[string]string{
	knowledge.SourceOSV:          "osv_id",
	knowledge.SourceNVD:          "nvd_id",
	knowledge.SourceGCVE:         "gcve_id",
	knowledge.SourceFriendsOfPHP: "friendsofphp_id",
}

// counts holds the numbers a source's floors apply to.
type counts struct {
	rows      int64
	malicious *int64
}

// Run validates every source at the time now and records each source's result.
func Run(db *bun.DB, now time.Time) (Report, error) {
	ctx := context.Background()
	var report Report
	for _, source := range sources {
		current, err := countSource(ctx, db, source)
		if err != nil {
			return report, fmt.Errorf("%s: count rows: %w", source, err)
		}
		floors, err := readFloors(ctx, db, source)
		if err != nil {
			return report, fmt.Errorf("%s: read floors: %w", source, err)
		}
		findings := checkCounts(source, current, floors)
		freshness, err := checkFreshness(ctx, db, source, now)
		if err != nil {
			return report, fmt.Errorf("%s: read watermark: %w", source, err)
		}
		findings = append(findings, freshness...)
		integrity, err := checkIntegrity(ctx, db, source)
		if err != nil {
			return report, fmt.Errorf("%s: check integrity: %w", source, err)
		}
		findings = append(findings, integrity...)
		report.Findings = append(report.Findings, findings...)
		if err := record(ctx, db, source, current, findings, now); err != nil {
			return report, fmt.Errorf("%s: record validation: %w", source, err)
		}
	}
	return report, nil
}

// floors holds the counts recorded at a source's last passing validation.
type floors struct {
	rows      *int64
	malicious *int64
}

func readFloors(ctx context.Context, db *bun.DB, source string) (floors, error) {
	var row floors
	err := db.QueryRowContext(ctx,
		"SELECT validated_row_count, validated_malicious_count FROM knowledge_source_sync WHERE source = ?", source).
		Scan(&row.rows, &row.malicious)
	if errors.Is(err, sql.ErrNoRows) {
		return floors{}, nil
	}
	return row, err
}

// checkCounts fails a source with no rows or with a count too far below its floor.
func checkCounts(source string, current counts, floor floors) []Finding {
	var findings []Finding
	if current.rows == 0 {
		findings = append(findings, Finding{source, CheckRowCount, "source has no active rows"})
	} else if dropped(current.rows, floor.rows) {
		findings = append(findings, Finding{source, CheckRowCount, dropMessage(current.rows, *floor.rows)})
	}
	if current.malicious != nil && dropped(*current.malicious, floor.malicious) {
		findings = append(findings, Finding{source, CheckMaliciousCount, dropMessage(*current.malicious, *floor.malicious)})
	}
	return findings
}

// dropped reports a fall of more than maxDropPercent below the floor.
func dropped(current int64, floor *int64) bool {
	return floor != nil && current*100 < *floor*(100-maxDropPercent)
}

func dropMessage(current, floor int64) string {
	return fmt.Sprintf("%d active rows is more than %d%% below the last validated %d", current, maxDropPercent, floor)
}

// checkFreshness fails a source whose watermark is missing or past its threshold.
func checkFreshness(ctx context.Context, db *bun.DB, source string, now time.Time) ([]Finding, error) {
	var watermark sql.NullTime
	err := db.QueryRowContext(ctx, "SELECT watermark FROM knowledge_source_sync WHERE source = ?", source).Scan(&watermark)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if !watermark.Valid {
		return []Finding{{source, CheckFreshness, "source has no watermark"}}, nil
	}
	limit := staleAfter[source]
	if now.Sub(watermark.Time) > limit {
		return []Finding{{source, CheckFreshness, fmt.Sprintf("watermark %s is older than %s", watermark.Time.UTC().Format(time.RFC3339), limit)}}, nil
	}
	return nil, nil
}

// checkIntegrity fails a source whose package links point at missing or retired advisories.
func checkIntegrity(ctx context.Context, db *bun.DB, source string) ([]Finding, error) {
	column, linked := linkColumns[source]
	if !linked {
		return nil, nil
	}
	var missing, retired int64
	err := db.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE a.id IS NULL), count(*) FILTER (WHERE a.retired_at IS NOT NULL)
		FROM package_vulnerability pv LEFT JOIN ? a ON a.id = pv.?
		WHERE pv.? IS NOT NULL`, bun.Ident(source), bun.Ident(column), bun.Ident(column)).Scan(&missing, &retired)
	if err != nil {
		return nil, err
	}
	if missing == 0 && retired == 0 {
		return nil, nil
	}
	return []Finding{{source, CheckIntegrity, fmt.Sprintf("%d package links to missing advisories, %d to retired advisories", missing, retired)}}, nil
}

// ResetRowFloors forgets the floors of the given sources, for a reviewed
// legitimate reset. The next passing validation sets them again.
func ResetRowFloors(db *bun.DB, resetSources ...string) error {
	_, err := db.NewUpdate().
		Table("knowledge_source_sync").
		Set("validated_row_count = NULL, validated_malicious_count = NULL").
		Where("source IN (?)", bun.In(resetSources)).
		Exec(context.Background())
	if err != nil {
		return fmt.Errorf("reset row floors: %w", err)
	}
	return nil
}

// countSource counts active rows, and for OSV counts each advisory kind separately.
func countSource(ctx context.Context, db *bun.DB, source string) (counts, error) {
	switch source {
	case knowledge.SourceOSV:
		rows, err := countWhere(ctx, db, source, "retired_at IS NULL AND kind = 'vulnerability'")
		if err != nil {
			return counts{}, err
		}
		malicious, err := countWhere(ctx, db, source, "retired_at IS NULL AND kind = 'malicious'")
		if err != nil {
			return counts{}, err
		}
		return counts{rows: rows, malicious: &malicious}, nil
	case knowledge.SourceNVD, knowledge.SourceGCVE, knowledge.SourceFriendsOfPHP:
		rows, err := countWhere(ctx, db, source, "retired_at IS NULL")
		return counts{rows: rows}, err
	default:
		rows, err := countWhere(ctx, db, source, "TRUE")
		return counts{rows: rows}, err
	}
}

func countWhere(ctx context.Context, db *bun.DB, table, condition string) (int64, error) {
	var rows int64
	err := db.NewSelect().TableExpr("?", bun.Ident(table)).ColumnExpr("count(*)").Where(condition).Scan(ctx, &rows)
	return rows, err
}

// record stores the outcome. Floors only move when the source passed.
func record(ctx context.Context, db *bun.DB, source string, current counts, findings []Finding, now time.Time) error {
	var validationError *string
	if len(findings) > 0 {
		messages := make([]string, len(findings))
		for i, finding := range findings {
			messages[i] = finding.Check + ": " + finding.Message
		}
		joined := strings.Join(messages, "; ")
		validationError = &joined
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO knowledge_source_sync (source, validation_error) VALUES (?, ?)
		ON CONFLICT (source) DO UPDATE SET
			validation_error = EXCLUDED.validation_error,
			validated_row_count = CASE WHEN ? THEN ? ELSE knowledge_source_sync.validated_row_count END,
			validated_malicious_count = CASE WHEN ? THEN ? ELSE knowledge_source_sync.validated_malicious_count END,
			validated_at = CASE WHEN ? THEN ?::timestamptz ELSE knowledge_source_sync.validated_at END`,
		source, validationError,
		validationError == nil, current.rows,
		validationError == nil, current.malicious,
		validationError == nil, now)
	return err
}
