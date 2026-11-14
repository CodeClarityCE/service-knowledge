package sourcesync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

var previousWatermark = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func seed(t *testing.T, db *bun.DB) {
	t.Helper()
	_, err := db.ExecContext(context.Background(),
		"INSERT INTO knowledge_source_sync (source, watermark) VALUES (?, ?)", knowledge.SourceEPSS, previousWatermark)
	if err != nil {
		t.Fatal(err)
	}
	// Run counts rows in the table named after the source.
	if _, err := db.ExecContext(context.Background(), "CREATE TABLE epss (id int); INSERT INTO epss VALUES (1), (2)"); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, db *bun.DB, source string) knowledge.SourceSync {
	t.Helper()
	row := knowledge.SourceSync{Source: source}
	if err := db.NewSelect().Model(&row).WherePK().Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	return row
}

func TestSuccessfulRunAdvancesWatermarkAndRecordsOutcome(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	seed(t, db)
	synced := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	err := Run(db, knowledge.SourceEPSS, func() (time.Time, error) { return synced, nil })
	if err != nil {
		t.Fatal(err)
	}

	row := read(t, db, knowledge.SourceEPSS)
	if row.Watermark == nil || !row.Watermark.Equal(synced) {
		t.Errorf("watermark = %v, want %v", row.Watermark, synced)
	}
	if row.LastOutcome == nil || *row.LastOutcome != knowledge.SourceSyncSuccess {
		t.Errorf("outcome = %v", row.LastOutcome)
	}
	if row.LastError != nil {
		t.Errorf("last_error = %q, want NULL", *row.LastError)
	}
	if row.LastRunStartedAt == nil || row.LastRunFinishedAt == nil {
		t.Error("run timestamps should be set")
	}
	if row.RowCount != 2 {
		t.Errorf("row_count = %d, want 2", row.RowCount)
	}
}

func TestFailedRunKeepsWatermarkAndRecordsError(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	seed(t, db)
	failure := errors.New("batch 3 failed")

	err := Run(db, knowledge.SourceEPSS, func() (time.Time, error) { return time.Time{}, failure })
	if !errors.Is(err, failure) {
		t.Fatalf("got %v, want the sync's own error", err)
	}

	row := read(t, db, knowledge.SourceEPSS)
	if row.Watermark == nil || !row.Watermark.Equal(previousWatermark) {
		t.Errorf("watermark = %v, want unchanged %v", row.Watermark, previousWatermark)
	}
	if row.LastOutcome == nil || *row.LastOutcome != knowledge.SourceSyncFailure {
		t.Errorf("outcome = %v", row.LastOutcome)
	}
	if row.LastError == nil || *row.LastError != "batch 3 failed" {
		t.Errorf("last_error = %v", row.LastError)
	}
}

func TestFailedRunIgnoresCompletedProgress(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	seed(t, db)
	window := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	_ = Run(db, knowledge.SourceEPSS, func() (time.Time, error) { return window, errors.New("next window failed") })

	row := read(t, db, knowledge.SourceEPSS)
	if !row.Watermark.Equal(previousWatermark) {
		t.Errorf("watermark = %v, want unchanged %v", row.Watermark, previousWatermark)
	}
	if *row.LastOutcome != knowledge.SourceSyncFailure {
		t.Errorf("outcome = %v", *row.LastOutcome)
	}
}

func TestRunInProgressHasStartedButNotFinished(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	seed(t, db)

	var during knowledge.SourceSync
	err := Run(db, knowledge.SourceEPSS, func() (time.Time, error) {
		during = read(t, db, knowledge.SourceEPSS)
		return time.Now(), nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if during.LastRunStartedAt == nil {
		t.Error("last_run_started_at should be set when the run starts")
	}
	if during.LastRunFinishedAt != nil || during.LastOutcome != nil {
		t.Error("a first run in progress has neither finish time nor outcome")
	}
}

func TestPanicIsRecordedAsFailure(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	seed(t, db)

	err := Run(db, knowledge.SourceEPSS, func() (time.Time, error) { panic("parser exploded") })
	if err == nil || !strings.Contains(err.Error(), "parser exploded") {
		t.Fatalf("err = %v, want it to name the panic", err)
	}
	if *read(t, db, knowledge.SourceEPSS).LastOutcome != knowledge.SourceSyncFailure {
		t.Error("a panic should be recorded as a failure")
	}
}

func TestLongErrorsAreTruncatedForStorage(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	seed(t, db)

	_ = Run(db, knowledge.SourceEPSS, func() (time.Time, error) {
		return time.Time{}, errors.New(strings.Repeat("x", 3*maxStoredErrorLength) + "\x00")
	})

	stored := *read(t, db, knowledge.SourceEPSS).LastError
	if len(stored) != maxStoredErrorLength {
		t.Errorf("stored %d bytes, want %d", len(stored), maxStoredErrorLength)
	}
}

func TestRecordingFailureIsAnError(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	if _, err := db.ExecContext(context.Background(), "DROP TABLE knowledge_source_sync"); err != nil {
		t.Fatal(err)
	}

	ran := false
	err := Run(db, knowledge.SourceEPSS, func() (time.Time, error) { ran = true; return time.Now(), nil })
	if err == nil {
		t.Fatal("a run that cannot be recorded should fail")
	}
	if ran {
		t.Error("the sync should not run when its start cannot be recorded")
	}
}

func TestWatermarkReadsNilAsZero(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	got, err := Watermark(db, knowledge.SourceNVD)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsZero() {
		t.Errorf("got %v, want zero", got)
	}
}

func TestFailureLogCarriesStructuredFields(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	seed(t, db)
	var output bytes.Buffer
	logger.SetOutput(&output)
	t.Cleanup(func() { logger.SetOutput(defaultLogOutput) })

	_ = Run(db, knowledge.SourceEPSS, func() (time.Time, error) { return time.Time{}, errors.New("boom") })

	var entry map[string]any
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatalf("log line is not JSON: %v", err)
	}
	if entry["level"] != "error" || entry["source"] != "epss" || entry["outcome"] != "failure" || entry["error"] != "boom" {
		t.Errorf("entry = %v", entry)
	}
	if _, ok := entry["duration_seconds"]; !ok {
		t.Errorf("entry = %v, want duration_seconds", entry)
	}
}

func TestSuccessfulRunRecordsTheUpstreamTotal(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	seed(t, db)

	err := RunCounted(db, knowledge.SourceEPSS, func() (Result, error) {
		return Result{Watermark: time.Now(), UpstreamTotal: Total(2)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := testhelper.UpstreamTotal(t, db, knowledge.SourceEPSS); got == nil || *got != 2 {
		t.Errorf("upstream_total = %v, want 2", got)
	}
}

func TestRunWithoutATotalKeepsTheRecordedOne(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	seed(t, db)
	if err := RunCounted(db, knowledge.SourceEPSS, func() (Result, error) {
		return Result{Watermark: time.Now(), UpstreamTotal: Total(2)}, nil
	}); err != nil {
		t.Fatal(err)
	}

	// An incremental run sees only a window of upstream.
	err := RunCounted(db, knowledge.SourceEPSS, func() (Result, error) {
		return Result{Watermark: time.Now()}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := testhelper.UpstreamTotal(t, db, knowledge.SourceEPSS); got == nil || *got != 2 {
		t.Errorf("upstream_total = %v, want the earlier 2 kept", got)
	}
}

func TestFailedRunKeepsTheRecordedTotal(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	seed(t, db)
	if err := RunCounted(db, knowledge.SourceEPSS, func() (Result, error) {
		return Result{Watermark: time.Now(), UpstreamTotal: Total(2)}, nil
	}); err != nil {
		t.Fatal(err)
	}

	_ = RunCounted(db, knowledge.SourceEPSS, func() (Result, error) {
		return Result{UpstreamTotal: Total(9)}, errors.New("store failed")
	})

	if got := testhelper.UpstreamTotal(t, db, knowledge.SourceEPSS); got == nil || *got != 2 {
		t.Errorf("upstream_total = %v, want the earlier 2 kept", got)
	}
}

func TestUpstreamWithNoRecordsFailsTheSource(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	seed(t, db)

	err := RunCounted(db, knowledge.SourceEPSS, func() (Result, error) {
		return Result{Watermark: time.Now(), UpstreamTotal: Total(0)}, nil
	})

	if !errors.Is(err, ErrNoUpstreamRecords) {
		t.Fatalf("err = %v, want ErrNoUpstreamRecords", err)
	}
	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceEPSS, previousWatermark)
	if got := testhelper.UpstreamTotal(t, db, knowledge.SourceEPSS); got != nil {
		t.Errorf("upstream_total = %v, want none recorded", *got)
	}
}
