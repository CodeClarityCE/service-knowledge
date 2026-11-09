package knowledge

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/datedrestore"
	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
)

func TestRefetchClearsEachWatermarkBeforeItsSync(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	testhelper.SeedWatermark(t, db, knowledge_db.SourceNVD, time.Now())
	testhelper.SeedWatermark(t, db, knowledge_db.SourceGCVE, time.Now())
	if err := sourcesync.SetBulkCompletedAt(db, knowledge_db.SourceGCVE, time.Now()); err != nil {
		t.Fatal(err)
	}

	var ran []string
	sync := func(source string) func() error {
		return func() error {
			got, err := sourcesync.Watermark(db, source)
			if err != nil {
				t.Fatal(err)
			}
			if !got.IsZero() {
				t.Errorf("%s watermark = %v when its sync started, want none", source, got)
			}
			ran = append(ran, source)
			return nil
		}
	}

	err := refetchSources(db, []refetchSource{
		{knowledge_db.SourceNVD, sync(knowledge_db.SourceNVD)},
		{knowledge_db.SourceGCVE, sync(knowledge_db.SourceGCVE)},
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(ran) != 2 {
		t.Errorf("ran %v, want both sources", ran)
	}
	bulk, err := sourcesync.BulkCompletedAt(db, knowledge_db.SourceGCVE)
	if err != nil || !bulk.IsZero() {
		t.Errorf("bulk_completed_at = %v, err %v, want it cleared", bulk, err)
	}
}

func TestRefetchRunsEverySourceAndReportsFailures(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	secondRan := false
	boom := errors.New("boom")

	err := refetchSources(db, []refetchSource{
		{knowledge_db.SourceNVD, func() error { return boom }},
		{knowledge_db.SourceGCVE, func() error { secondRan = true; return nil }},
	})

	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want the failure reported", err)
	}
	if !secondRan {
		t.Error("the second source should still run")
	}
}

func TestRefetchClearsTheRowFloorOnlyForSourcesThatSucceeded(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	for _, source := range []string{knowledge_db.SourceNVD, knowledge_db.SourceGCVE} {
		testhelper.SeedWatermark(t, db, source, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	}
	if _, err := db.ExecContext(context.Background(), "UPDATE knowledge_source_sync SET validated_row_count = 100"); err != nil {
		t.Fatal(err)
	}

	err := refetchSources(db, []refetchSource{
		{knowledge_db.SourceNVD, func() error { return nil }},
		{knowledge_db.SourceGCVE, func() error { return errors.New("gcve failed") }},
	})
	if err == nil {
		t.Fatal("want the GCVE failure")
	}

	var cleared bool
	if err := db.QueryRowContext(context.Background(),
		"SELECT validated_row_count IS NULL FROM knowledge_source_sync WHERE source = 'nvd'").Scan(&cleared); err != nil || !cleared {
		t.Errorf("nvd floor should be cleared (err %v)", err)
	}
	if err := db.QueryRowContext(context.Background(),
		"SELECT validated_row_count IS NULL FROM knowledge_source_sync WHERE source = 'gcve'").Scan(&cleared); err != nil || cleared {
		t.Errorf("gcve floor should be kept (err %v)", err)
	}
}

func TestFullRefetchRefusesAMarkedDatabase(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	if _, err := db.ExecContext(context.Background(), "INSERT INTO knowledge_dated_restore (label) VALUES ('2025-01')"); err != nil {
		t.Fatal(err)
	}

	if err := FullRefetch(db, nil); !errors.Is(err, datedrestore.ErrDatedRestore) {
		t.Errorf("FullRefetch = %v, want ErrDatedRestore", err)
	}
}
