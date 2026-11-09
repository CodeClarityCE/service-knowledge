package knowledge

import (
	"errors"
	"testing"
	"time"

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
