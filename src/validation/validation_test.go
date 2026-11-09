package validation

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

const sourceTablesDDL = `
CREATE TABLE osv (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), kind varchar NOT NULL DEFAULT 'vulnerability', retired_at timestamptz);
CREATE TABLE nvd (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), retired_at timestamptz);
CREATE TABLE gcve (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), retired_at timestamptz);
CREATE TABLE friends_of_php (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), retired_at timestamptz);
CREATE TABLE epss (id uuid PRIMARY KEY DEFAULT gen_random_uuid());
CREATE TABLE cwe (id uuid PRIMARY KEY DEFAULT gen_random_uuid());
CREATE TABLE licenses (id uuid PRIMARY KEY DEFAULT gen_random_uuid());
CREATE TABLE package_vulnerability (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	osv_id uuid, nvd_id uuid, gcve_id uuid, friendsofphp_id uuid
);`

var now = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

var allSources = []string{
	knowledge.SourceCWE, knowledge.SourceEPSS, knowledge.SourceFriendsOfPHP, knowledge.SourceGCVE,
	knowledge.SourceLicenses, knowledge.SourceNVD, knowledge.SourceOSV,
}

func exec(t *testing.T, db *bun.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), query, args...); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

// setup makes every source hold rows and have a fresh watermark.
func setup(t *testing.T) *bun.DB {
	t.Helper()
	db := testhelper.SetupSyncTestDB(t)
	exec(t, db, sourceTablesDDL)
	for _, source := range allSources {
		exec(t, db, "INSERT INTO knowledge_source_sync (source, watermark) VALUES (?, ?)", source, now.Add(-time.Hour))
		addRows(t, db, source, 100)
	}
	addMalicious(t, db, 100)
	return db
}

func addRows(t *testing.T, db *bun.DB, table string, n int) {
	t.Helper()
	exec(t, db, "INSERT INTO ? (id) SELECT gen_random_uuid() FROM generate_series(1, ?)", bun.Ident(table), n)
}

func addMalicious(t *testing.T, db *bun.DB, n int) {
	t.Helper()
	exec(t, db, "INSERT INTO osv (kind) SELECT 'malicious' FROM generate_series(1, ?)", n)
}

func read(t *testing.T, db *bun.DB, source string) knowledge.SourceSync {
	t.Helper()
	row := knowledge.SourceSync{Source: source}
	if err := db.NewSelect().Model(&row).WherePK().Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	return row
}

func validate(t *testing.T, db *bun.DB) Report {
	t.Helper()
	report, err := Run(db, now)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func wantFinding(t *testing.T, report Report, source, check string) {
	t.Helper()
	for _, finding := range report.Findings {
		if finding.Source == source && finding.Check == check {
			return
		}
	}
	t.Errorf("no %s finding for %s in %+v", check, source, report.Findings)
}

func TestPassingValidationRecordsCountsAsFloors(t *testing.T) {
	db := setup(t)

	report := validate(t, db)

	if report.Failed() {
		t.Fatalf("unexpected findings: %+v", report.Findings)
	}
	row := read(t, db, knowledge.SourceNVD)
	if row.ValidatedRowCount == nil || *row.ValidatedRowCount != 100 {
		t.Errorf("validated_row_count = %v, want 100", row.ValidatedRowCount)
	}
	if row.ValidatedAt == nil || !row.ValidatedAt.Equal(now) {
		t.Errorf("validated_at = %v, want %v", row.ValidatedAt, now)
	}
	if row.ValidationError != nil {
		t.Errorf("validation_error = %q, want NULL", *row.ValidationError)
	}
}

// deleteVulnerabilities removes rows that are not malicious advisories.
func deleteVulnerabilities(t *testing.T, db *bun.DB, table string, n int) {
	t.Helper()
	filter := "TRUE"
	if table == knowledge.SourceOSV {
		filter = "kind = 'vulnerability'"
	}
	exec(t, db, "DELETE FROM ? WHERE id IN (SELECT id FROM ? WHERE "+filter+" LIMIT ?)", bun.Ident(table), bun.Ident(table), n)
}

func TestDropAboveFivePercentFailsAndKeepsTheFloor(t *testing.T) {
	db := setup(t)
	validate(t, db)
	deleteVulnerabilities(t, db, knowledge.SourceNVD, 6)

	report := validate(t, db)

	wantFinding(t, report, knowledge.SourceNVD, CheckRowCount)
	row := read(t, db, knowledge.SourceNVD)
	if row.ValidationError == nil {
		t.Error("validation_error should be set")
	}
	if *row.ValidatedRowCount != 100 {
		t.Errorf("validated_row_count = %d, want the last good 100", *row.ValidatedRowCount)
	}
}

func TestDropOfExactlyFivePercentPasses(t *testing.T) {
	db := setup(t)
	validate(t, db)
	deleteVulnerabilities(t, db, knowledge.SourceNVD, 5)

	if report := validate(t, db); report.Failed() {
		t.Errorf("unexpected findings: %+v", report.Findings)
	}
	if got := *read(t, db, knowledge.SourceNVD).ValidatedRowCount; got != 95 {
		t.Errorf("validated_row_count = %d, want 95", got)
	}
}

func TestSourceWithNoRowsFailsEvenWithoutAFloor(t *testing.T) {
	db := setup(t)
	exec(t, db, "DELETE FROM epss")

	wantFinding(t, validate(t, db), knowledge.SourceEPSS, CheckRowCount)
}

func TestRetiringRowsCountsAsADrop(t *testing.T) {
	db := setup(t)
	validate(t, db)
	exec(t, db, "UPDATE nvd SET retired_at = now() WHERE id IN (SELECT id FROM nvd LIMIT 10)")

	wantFinding(t, validate(t, db), knowledge.SourceNVD, CheckRowCount)
}

func TestLosingMaliciousAdvisoriesFailsWhenVulnerabilitiesHold(t *testing.T) {
	db := setup(t)
	validate(t, db)
	exec(t, db, "DELETE FROM osv WHERE kind = 'malicious'")

	report := validate(t, db)

	wantFinding(t, report, knowledge.SourceOSV, CheckMaliciousCount)
}

func TestMaliciousRowsDoNotMaskAVulnerabilityDrop(t *testing.T) {
	db := setup(t)
	addMalicious(t, db, 900)
	validate(t, db)
	deleteVulnerabilities(t, db, knowledge.SourceOSV, 20)

	wantFinding(t, validate(t, db), knowledge.SourceOSV, CheckRowCount)
}

func TestResetRowFloorsLetsTheNextValidationSetThem(t *testing.T) {
	db := setup(t)
	validate(t, db)
	deleteVulnerabilities(t, db, knowledge.SourceNVD, 50)
	if err := ResetRowFloors(db, knowledge.SourceNVD); err != nil {
		t.Fatal(err)
	}

	if report := validate(t, db); report.Failed() {
		t.Fatalf("unexpected findings: %+v", report.Findings)
	}
	if got := *read(t, db, knowledge.SourceNVD).ValidatedRowCount; got != 50 {
		t.Errorf("validated_row_count = %d, want 50", got)
	}
}

func TestAPassAfterAFailureClearsTheError(t *testing.T) {
	db := setup(t)
	validate(t, db)
	deleteVulnerabilities(t, db, knowledge.SourceNVD, 50)
	validate(t, db)
	addRows(t, db, knowledge.SourceNVD, 50)

	if report := validate(t, db); report.Failed() {
		t.Fatalf("unexpected findings: %+v", report.Findings)
	}
	if row := read(t, db, knowledge.SourceNVD); row.ValidationError != nil {
		t.Errorf("validation_error = %q, want NULL", *row.ValidationError)
	}
}

func TestSourcePastItsThresholdIsStale(t *testing.T) {
	cases := []struct {
		source string
		age    time.Duration
		stale  bool
	}{
		{knowledge.SourceOSV, 23 * time.Hour, false},
		{knowledge.SourceOSV, 25 * time.Hour, true},
		{knowledge.SourceEPSS, 25 * time.Hour, true},
		{knowledge.SourceNVD, 47 * time.Hour, false},
		{knowledge.SourceGCVE, 49 * time.Hour, true},
		{knowledge.SourceCWE, 6 * 24 * time.Hour, false},
		{knowledge.SourceLicenses, 8 * 24 * time.Hour, true},
		{knowledge.SourceFriendsOfPHP, 8 * 24 * time.Hour, true},
	}
	for _, c := range cases {
		t.Run(c.source, func(t *testing.T) {
			db := setup(t)
			exec(t, db, "UPDATE knowledge_source_sync SET watermark = ? WHERE source = ?", now.Add(-c.age), c.source)

			report := validate(t, db)

			if c.stale {
				wantFinding(t, report, c.source, CheckFreshness)
			} else if report.Failed() {
				t.Errorf("unexpected findings: %+v", report.Findings)
			}
		})
	}
}

func TestSourceWithNoWatermarkIsStale(t *testing.T) {
	db := setup(t)
	exec(t, db, "UPDATE knowledge_source_sync SET watermark = NULL WHERE source = 'gcve'")

	wantFinding(t, validate(t, db), knowledge.SourceGCVE, CheckFreshness)
}

func TestStaleSourceKeepsItsFloor(t *testing.T) {
	db := setup(t)
	validate(t, db)
	exec(t, db, "UPDATE knowledge_source_sync SET watermark = NULL WHERE source = 'nvd'")
	addRows(t, db, knowledge.SourceNVD, 50)

	validate(t, db)

	if got := *read(t, db, knowledge.SourceNVD).ValidatedRowCount; got != 100 {
		t.Errorf("validated_row_count = %d, want 100", got)
	}
}

func TestLinkToAMissingAdvisoryFailsTheSource(t *testing.T) {
	db := setup(t)
	exec(t, db, "INSERT INTO package_vulnerability (nvd_id) VALUES (gen_random_uuid())")

	wantFinding(t, validate(t, db), knowledge.SourceNVD, CheckIntegrity)
}

func TestLinkToARetiredAdvisoryFailsTheSource(t *testing.T) {
	db := setup(t)
	exec(t, db, "UPDATE gcve SET retired_at = now() WHERE id IN (SELECT id FROM gcve LIMIT 1)")
	exec(t, db, "INSERT INTO package_vulnerability (gcve_id) SELECT id FROM gcve WHERE retired_at IS NOT NULL")

	wantFinding(t, validate(t, db), knowledge.SourceGCVE, CheckIntegrity)
}

func TestValidLinksPass(t *testing.T) {
	db := setup(t)
	exec(t, db, "INSERT INTO package_vulnerability (osv_id) SELECT id FROM osv LIMIT 5")

	if report := validate(t, db); report.Failed() {
		t.Errorf("unexpected findings: %+v", report.Findings)
	}
}

func TestCheckThatCannotRunIsRecordedAndLaterSourcesStillRun(t *testing.T) {
	db := setup(t)
	validate(t, db)
	exec(t, db, "DROP TABLE gcve")

	report := validate(t, db)

	wantFinding(t, report, knowledge.SourceGCVE, CheckIncomplete)
	row := read(t, db, knowledge.SourceGCVE)
	if row.ValidationError == nil {
		t.Fatal("validation_error should record the incomplete validation")
	}
	if row.ValidatedRowCount == nil || *row.ValidatedRowCount != 100 {
		t.Errorf("validated_row_count = %v, want the last good 100", row.ValidatedRowCount)
	}
	if row := read(t, db, knowledge.SourceOSV); row.ValidationError != nil {
		t.Errorf("osv validation_error = %q, want NULL", *row.ValidationError)
	}
}

func TestStaleSourceIsNotRecordedAsAValidationFailure(t *testing.T) {
	db := setup(t)
	validate(t, db)
	exec(t, db, "UPDATE knowledge_source_sync SET watermark = NULL WHERE source = 'nvd'")

	report := validate(t, db)

	wantFinding(t, report, knowledge.SourceNVD, CheckFreshness)
	if row := read(t, db, knowledge.SourceNVD); row.ValidationError != nil {
		t.Errorf("validation_error = %q, want NULL so the source reads as stale", *row.ValidationError)
	}
}

func TestStaleSourceWithAnotherFailureKeepsOnlyThatFailure(t *testing.T) {
	db := setup(t)
	validate(t, db)
	exec(t, db, "UPDATE knowledge_source_sync SET watermark = NULL WHERE source = 'nvd'")
	deleteVulnerabilities(t, db, knowledge.SourceNVD, 50)

	validate(t, db)

	row := read(t, db, knowledge.SourceNVD)
	if row.ValidationError == nil || strings.Contains(*row.ValidationError, CheckFreshness) {
		t.Errorf("validation_error = %v, want only the row count failure", row.ValidationError)
	}
}
