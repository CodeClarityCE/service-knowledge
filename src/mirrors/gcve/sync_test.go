package gcve

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

var previous = time.Now().Add(-48 * time.Hour).Truncate(time.Second)

const record = `{"cveMetadata":{"cveId":"CVE-2026-0002","state":"PUBLISHED"},"containers":{"cna":{"affected":[{"vendor":"v","product":"p"}]}}}`

func setup(t *testing.T, watermark bool) *bun.DB {
	t.Helper()
	db := testhelper.SetupSyncTestDB(t)
	testhelper.CreateTables(t, db, (*knowledge.GCVEItem)(nil), (*knowledge.PackageVulnerability)(nil))
	testhelper.CreatePackageLinkIndexes(t, db)
	if _, err := db.ExecContext(context.Background(), "CREATE UNIQUE INDEX ON gcve (gcve_id)"); err != nil {
		t.Fatal(err)
	}
	if watermark {
		testhelper.SeedWatermark(t, db, knowledge.SourceGCVE, previous)
	}
	return db
}

// serve answers the incremental API with records and the dumps with dump.
// It returns a count of the bulk dump downloads.
func serve(t *testing.T, records, dump string, status int) *atomic.Int32 {
	t.Helper()
	bulkDownloads := &atomic.Int32{}
	mux := http.NewServeMux()
	mux.HandleFunc("/last", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, records) })
	mux.HandleFunc("/bulk", func(w http.ResponseWriter, _ *http.Request) {
		bulkDownloads.Add(1)
		w.WriteHeader(status)
		fmt.Fprint(w, dump)
	})
	mux.HandleFunc("/rich", func(w http.ResponseWriter, _ *http.Request) {})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	originalBulk, originalRich, originalLast := bulkDumpURL, vulnrichmentURL, lastUpdatedAPI
	bulkDumpURL, vulnrichmentURL, lastUpdatedAPI = server.URL+"/bulk", server.URL+"/rich", server.URL+"/last"
	t.Cleanup(func() { bulkDumpURL, vulnrichmentURL, lastUpdatedAPI = originalBulk, originalRich, originalLast })
	return bulkDownloads
}

func TestBatchFailureLeavesWatermark(t *testing.T) {
	db := setup(t, true)
	testhelper.DropTable(t, db, "gcve")
	serve(t, "["+record+"]", record, http.StatusOK)

	if err := Update(db, db); err == nil {
		t.Fatal("a failed batch should fail the source")
	}
	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceGCVE, previous)
}

func TestPackageLinkFailureLeavesWatermark(t *testing.T) {
	db := setup(t, true)
	testhelper.DropTable(t, db, "package_vulnerability")
	serve(t, "["+record+"]", record, http.StatusOK)

	if err := Update(db, db); err == nil {
		t.Fatal("a failed package link insert should fail the source")
	}
	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceGCVE, previous)
}

func TestUnparsableRecordLeavesWatermark(t *testing.T) {
	db := setup(t, true)
	serve(t, `[{"cveMetadata":"not an object"}]`, `{"cveMetadata":"not an object"}`, http.StatusOK)

	if err := Update(db, db); err == nil {
		t.Fatal("an unparsable record should fail the source")
	}
	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceGCVE, previous)
}

func TestIncrementalSuccessAdvancesWatermarkWithoutClobberingConfig(t *testing.T) {
	db := setup(t, true)
	otherWriter := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	serve(t, "["+record+"]", "", http.StatusOK)
	testhelper.SetConfigTime(t, db, "nvd_last", otherWriter)

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}
	testhelper.AssertSucceededAfter(t, db, knowledge.SourceGCVE, previous)
	if got := testhelper.ConfigTime(t, db, "nvd_last"); !got.Equal(otherWriter) {
		t.Errorf("nvd_last = %v, want the other writer's %v", got, otherWriter)
	}
	if got := testhelper.ConfigTime(t, db, "gcve_last"); !got.After(previous) {
		t.Errorf("gcve_last = %v, want it advanced", got)
	}
}

func TestFirstRunUsesBulkImport(t *testing.T) {
	db := setup(t, false)
	serve(t, "[]", record, http.StatusOK)

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}
	testhelper.AssertSucceededAfter(t, db, knowledge.SourceGCVE, time.Time{})
	var rows int
	if err := db.NewSelect().Table("gcve").ColumnExpr("count(*)").Scan(context.Background(), &rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("rows = %d, want the bulk record", rows)
	}
}

func TestFailedDumpDownloadLeavesNoWatermark(t *testing.T) {
	db := setup(t, false)
	serve(t, "[]", "", http.StatusBadGateway)

	if err := Update(db, db); err == nil {
		t.Fatal("a failed dump download should fail the source")
	}
	if got := testhelper.ConfigTimeIsNull(t, db, "gcve_last"); !got {
		t.Error("gcve_last should stay unset")
	}
}

func TestBadIncrementalRecordDoesNotDownloadBulkDump(t *testing.T) {
	db := setup(t, true)
	bulkDownloads := serve(t, `[{"cveMetadata":"not an object"},`+record+`]`, record, http.StatusOK)

	if err := Update(db, db); err == nil {
		t.Fatal("an unparsable record should fail the source")
	}
	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceGCVE, previous)
	if got := bulkDownloads.Load(); got != 0 {
		t.Errorf("bulk downloads = %d, want 0", got)
	}
}

func TestIncrementalBatchFailureDoesNotDownloadBulkDump(t *testing.T) {
	db := setup(t, true)
	testhelper.DropTable(t, db, "package_vulnerability")
	bulkDownloads := serve(t, "["+record+"]", record, http.StatusOK)

	if err := Update(db, db); err == nil {
		t.Fatal("a failed batch should fail the source")
	}
	if got := bulkDownloads.Load(); got != 0 {
		t.Errorf("bulk downloads = %d, want 0", got)
	}
}

func TestUnreadableIncrementalResponseFallsBackToBulkDump(t *testing.T) {
	db := setup(t, true)
	bulkDownloads := serve(t, "not json", record, http.StatusOK)

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}
	testhelper.AssertSucceededAfter(t, db, knowledge.SourceGCVE, previous)
	if got := bulkDownloads.Load(); got != 1 {
		t.Errorf("bulk downloads = %d, want 1", got)
	}
}

func TestVulnrichmentFailureFailsSourceWithoutSecondBulkDownload(t *testing.T) {
	db := setup(t, false)
	bulkDownloads := serve(t, "[]", record, http.StatusOK)
	vulnrichmentURL = lastUpdatedAPI + "/missing"

	if err := Update(db, db); err == nil {
		t.Fatal("a failed vulnrichment import should fail the source")
	}
	if !testhelper.ConfigTimeIsNull(t, db, "gcve_last") {
		t.Error("gcve_last should stay unset")
	}
	if got := bulkDownloads.Load(); got != 1 {
		t.Errorf("bulk downloads = %d, want 1", got)
	}
}
