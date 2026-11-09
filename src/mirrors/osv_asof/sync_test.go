package osv_asof

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/datedrestore"
	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

var seededWatermark = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

// setupSync creates the OSV tables and an osv sync row that has a recorded failure.
func setupSync(t *testing.T) *bun.DB {
	t.Helper()
	db := testhelper.SetupSyncTestDB(t)
	testhelper.CreateTables(t, db, (*knowledge.OSVItem)(nil), (*knowledge.PackageVulnerability)(nil))
	testhelper.CreatePackageLinkIndexes(t, db)
	if _, err := db.ExecContext(context.Background(), "CREATE UNIQUE INDEX ON osv (osv_id)"); err != nil {
		t.Fatal(err)
	}
	testhelper.SeedWatermark(t, db, knowledge.SourceOSV, seededWatermark)
	if _, err := db.ExecContext(context.Background(), "INSERT INTO knowledge_dated_restore (label) VALUES ('test')"); err != nil {
		t.Fatal(err)
	}
	_, err := db.ExecContext(context.Background(),
		"UPDATE knowledge_source_sync SET last_outcome = 'failure', last_error = 'earlier', row_count = 7")
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// assertOnlyWatermarkMoved checks the OSV watermark and osv_last are want and the run outcome is untouched.
func assertOnlyWatermarkMoved(t *testing.T, db *bun.DB, want time.Time) {
	t.Helper()
	got, err := sourcesync.Watermark(db, knowledge.SourceOSV)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Errorf("watermark = %v, want %v", got, want)
	}
	if last := testhelper.ConfigTime(t, db, "osv_last"); !last.Equal(want) {
		t.Errorf("osv_last = %v, want %v", last, want)
	}
	var outcome, lastError string
	var rows int64
	err = db.QueryRowContext(context.Background(),
		"SELECT last_outcome, last_error, row_count FROM knowledge_source_sync WHERE source = 'osv'",
	).Scan(&outcome, &lastError, &rows)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != "failure" || lastError != "earlier" || rows != 7 {
		t.Errorf("other columns changed: outcome=%s error=%s rows=%d", outcome, lastError, rows)
	}
}

func TestFilterMovesOSVWatermark(t *testing.T) {
	db := setupSync(t)

	if err := Filter(db, db, testAsof); err != nil {
		t.Fatal(err)
	}
	assertOnlyWatermarkMoved(t, db, testAsof)
}

func TestUpdateMovesOSVWatermarkToCheckoutDate(t *testing.T) {
	db := setupSync(t)
	checkout := testAsof.Add(36 * time.Hour)

	if err := Update(db, db, "testdata/advisory-db", testAsof, checkout); err != nil {
		t.Fatal(err)
	}
	assertOnlyWatermarkMoved(t, db, checkout)
}

func TestFilterCreatesMissingOSVSyncRow(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	testhelper.CreateTables(t, db, (*knowledge.OSVItem)(nil), (*knowledge.PackageVulnerability)(nil))
	if _, err := db.ExecContext(context.Background(), "INSERT INTO knowledge_dated_restore (label) VALUES ('test')"); err != nil {
		t.Fatal(err)
	}

	if err := Filter(db, db, testAsof); err != nil {
		t.Fatal(err)
	}
	got, err := sourcesync.Watermark(db, knowledge.SourceOSV)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(testAsof) {
		t.Errorf("watermark = %v, want %v", got, testAsof)
	}
}

func TestFilterRefusesAnUnmarkedDatabase(t *testing.T) {
	db := setupSync(t)
	if _, err := db.ExecContext(context.Background(), "DELETE FROM knowledge_dated_restore"); err != nil {
		t.Fatal(err)
	}

	err := Filter(db, db, testAsof)

	if !errors.Is(err, datedrestore.ErrNotDatedRestore) {
		t.Fatalf("Filter = %v, want ErrNotDatedRestore", err)
	}
	if got, err := sourcesync.Watermark(db, knowledge.SourceOSV); err != nil || !got.Equal(seededWatermark) {
		t.Errorf("watermark = %v (err %v), want %v", got, err, seededWatermark)
	}
}
