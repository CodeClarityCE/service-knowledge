package pgsql

import (
	"context"
	"testing"
	"time"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// Same shape as these tables after the ExtendKnowledgeSoundTypes API migration.
const soundTypesTestSchema = `
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE osv (
	id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
	osv_id varchar NOT NULL UNIQUE,
	schema_version varchar, vlai_score varchar, vlai_confidence double precision,
	modified timestamptz, published timestamptz, withdrawn timestamptz,
	aliases jsonb, related jsonb, summary varchar, details varchar, severity jsonb,
	affected jsonb, "references" jsonb, credits jsonb, database_specific jsonb,
	cwes jsonb, cve varchar,
	retired_reason varchar, retired_at timestamptz,
	kind varchar NOT NULL DEFAULT 'vulnerability',
	cve_aliases jsonb GENERATED ALWAYS AS (
		COALESCE(jsonb_path_query_array(aliases, '$[*] ? (@ starts with "CVE-")'), '[]'::jsonb)
	) STORED
);
CREATE TABLE epss (
	id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
	cve varchar NOT NULL UNIQUE, score double precision, percentile double precision,
	score_date date
);`

func readOsv(t *testing.T, db *bun.DB, id string) knowledge.OSVItem {
	t.Helper()
	var item knowledge.OSVItem
	if err := db.NewSelect().Model(&item).Where("osv_id = ?", id).Scan(context.Background()); err != nil {
		t.Fatalf("read %s: %v", id, err)
	}
	return item
}

func TestOsvDatesRoundTripThroughTimestamptz(t *testing.T) {
	db := setupTestDB(t, soundTypesTestSchema)

	err := BatchUpdateOsv(db, []knowledge.OSVItem{{
		OSVId:     "GHSA-nanos",
		Modified:  "2026-03-23T05:06:54.289219582Z",
		Published: "2019-12-20T02:08:50Z",
		Withdrawn: "",
	}})
	if err != nil {
		t.Fatalf("batch upsert: %v", err)
	}

	item := readOsv(t, db, "GHSA-nanos")
	if item.Withdrawn != "" {
		t.Errorf("Withdrawn = %q, want empty for an unset date", item.Withdrawn)
	}
	published, err := time.Parse(time.RFC3339, item.Published)
	if err != nil {
		t.Fatalf("Published %q is not RFC 3339: %v", item.Published, err)
	}
	if want := time.Date(2019, 12, 20, 2, 8, 50, 0, time.UTC); !published.Equal(want) {
		t.Errorf("Published = %s, want %s", published, want)
	}
	modified, err := time.Parse(time.RFC3339, item.Modified)
	if err != nil {
		t.Fatalf("Modified %q is not RFC 3339: %v", item.Modified, err)
	}
	if want := time.Date(2026, 3, 23, 5, 6, 54, 289220000, time.UTC); !modified.Equal(want) {
		t.Errorf("Modified = %s, want %s", modified, want)
	}
}

func TestOsvUpsertKeepsRetirementAndKind(t *testing.T) {
	db := setupTestDB(t, soundTypesTestSchema)
	ctx := context.Background()
	if err := UpdateOsv(db, knowledge.OSVItem{OSVId: "MAL-2024-1"}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	retired := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	_, err := db.NewUpdate().Model((*knowledge.OSVItem)(nil)).
		Set("retired_reason = ?", knowledge.RetiredRemoved).
		Set("retired_at = ?", retired).
		Set("kind = ?", knowledge.AdvisoryKindMalicious).
		Where("osv_id = ?", "MAL-2024-1").
		Exec(ctx)
	if err != nil {
		t.Fatalf("retire: %v", err)
	}

	if err := UpdateOsv(db, knowledge.OSVItem{OSVId: "MAL-2024-1", Summary: "again"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	item := readOsv(t, db, "MAL-2024-1")
	if item.RetiredReason != knowledge.RetiredRemoved || !item.RetiredAt.Equal(retired) {
		t.Errorf("retirement = %q %s, want it unchanged", item.RetiredReason, item.RetiredAt)
	}
	if item.Kind != knowledge.AdvisoryKindMalicious {
		t.Errorf("Kind = %q, want it unchanged", item.Kind)
	}
}

func TestOsvNewRowDefaultsToVulnerability(t *testing.T) {
	db := setupTestDB(t, soundTypesTestSchema)

	if err := UpdateOsv(db, knowledge.OSVItem{OSVId: "GHSA-new"}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	item := readOsv(t, db, "GHSA-new")
	if item.Kind != knowledge.AdvisoryKindVulnerability {
		t.Errorf("Kind = %q, want %q", item.Kind, knowledge.AdvisoryKindVulnerability)
	}
	if !item.RetiredAt.IsZero() || item.RetiredReason != "" {
		t.Errorf("new record is retired: %q %s", item.RetiredReason, item.RetiredAt)
	}
}

func TestOsvCveAliasesAreReadableAndNotWritten(t *testing.T) {
	db := setupTestDB(t, soundTypesTestSchema)

	err := UpdateOsv(db, knowledge.OSVItem{
		OSVId:   "GHSA-557v",
		Aliases: []string{"GHSA-73jg", "CVE-2023-51651", "CVE-2025-69820"},
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Bun leaves scanonly columns out of a model select, so name it.
	var item knowledge.OSVItem
	err = db.NewSelect().Model(&item).ColumnExpr("cve_aliases").Where("osv_id = ?", "GHSA-557v").Scan(context.Background())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	want := []string{"CVE-2023-51651", "CVE-2025-69820"}
	if len(item.CveAliases) != 2 || item.CveAliases[0] != want[0] || item.CveAliases[1] != want[1] {
		t.Errorf("CveAliases = %v, want %v", item.CveAliases, want)
	}
}

func TestEpssScoreDateIsStoredOnInsert(t *testing.T) {
	db := setupTestDB(t, soundTypesTestSchema)
	scored := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)

	if err := UpdateEPSS(db, []knowledge.EPSS{{CVE: "CVE-2024-1", Score: 0.5, ScoreDate: scored}}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	var row knowledge.EPSS
	if err := db.NewSelect().Model(&row).Where("cve = ?", "CVE-2024-1").Scan(context.Background()); err != nil {
		t.Fatalf("read: %v", err)
	}
	if row.ScoreDate.Format("2006-01-02") != "2026-11-08" {
		t.Errorf("ScoreDate = %s, want 2026-11-08", row.ScoreDate)
	}
}

func TestEpssUpdateChangesExistingScoreAndDate(t *testing.T) {
	db := setupTestDB(t, soundTypesTestSchema)
	first := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	second := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)

	if err := UpdateEPSS(db, []knowledge.EPSS{{CVE: "CVE-2024-1", Score: 0.1, Percentile: 0.2, ScoreDate: first}}); err != nil {
		t.Fatal(err)
	}
	if err := UpdateEPSS(db, []knowledge.EPSS{{CVE: "CVE-2024-1", Score: 0.5, Percentile: 0.6, ScoreDate: second}}); err != nil {
		t.Fatal(err)
	}

	var row knowledge.EPSS
	if err := db.NewSelect().Model(&row).Where("cve = ?", "CVE-2024-1").Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if row.Score != 0.5 || row.Percentile != 0.6 || row.ScoreDate.Format("2006-01-02") != "2026-11-08" {
		t.Errorf("row = %+v, want the second score and date", row)
	}
}

func TestEpssUpdateAcceptsRepeatedCVE(t *testing.T) {
	db := setupTestDB(t, soundTypesTestSchema)
	err := UpdateEPSS(db, []knowledge.EPSS{{CVE: "CVE-2024-1", Score: 0.1}, {CVE: "CVE-2024-1", Score: 0.9}})
	if err != nil {
		t.Fatal(err)
	}
	var score float32
	if err := db.NewRaw("SELECT score FROM epss").Scan(context.Background(), &score); err != nil || score != 0.9 {
		t.Errorf("score = %v, err %v, want the last value 0.9", score, err)
	}
}
