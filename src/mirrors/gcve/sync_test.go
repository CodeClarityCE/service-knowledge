package gcve

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
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

// serve answers the incremental API with records and both dumps with dump.
// It returns a count of the bulk dump downloads.
func serve(t *testing.T, records, dump string, status int) *atomic.Int32 {
	t.Helper()
	bulkDownloads := &atomic.Int32{}
	mux := http.NewServeMux()
	mux.HandleFunc("/last", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, records) })
	mux.HandleFunc("/bulk", func(w http.ResponseWriter, _ *http.Request) {
		bulkDownloads.Add(1)
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.WriteHeader(status)
		fmt.Fprint(w, dump)
	})
	// Vulnrichment enriches records the dump already holds.
	mux.HandleFunc("/rich", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, dump) })
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	t.Cleanup(UseUpstream(server.URL+"/bulk", server.URL+"/rich", server.URL+"/last"))
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
	vulnrichmentURL = vulnerabilityAPI + "/missing"

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

const enrichedRecord = `{"cveMetadata":{"cveId":"CVE-2026-0003","state":"PUBLISHED"},"containers":{"cna":{"affected":[{"vendor":"v","product":"q"}]}}}`

// serveEnrichment points the enrichment dump at a server answering with status and body.
func serveEnrichment(t *testing.T, status int, body string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(server.Close)
	vulnrichmentURL = server.URL
}

func bulkCompletedAt(t *testing.T, db *bun.DB) time.Time {
	t.Helper()
	completedAt, err := sourcesync.BulkCompletedAt(db, knowledge.SourceGCVE)
	if err != nil {
		t.Fatal(err)
	}
	return completedAt
}

func watermark(t *testing.T, db *bun.DB) time.Time {
	t.Helper()
	value, err := sourcesync.Watermark(db, knowledge.SourceGCVE)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestEnrichmentRetryReadsTheDumpAgainAndAdvancesFromRunStart(t *testing.T) {
	db := setup(t, false)
	bulkDownloads := serve(t, "[]", record, http.StatusOK)
	serveEnrichment(t, http.StatusBadGateway, "")

	before := time.Now().Truncate(time.Second)
	if err := Update(db, db); err == nil {
		t.Fatal("a failed enrichment should fail the source")
	}
	afterFirstRun := time.Now()

	completedAt := bulkCompletedAt(t, db)
	if completedAt.Before(before) || completedAt.After(afterFirstRun) {
		t.Fatalf("bulk_completed_at = %v, want a time during the first run", completedAt)
	}
	testhelper.AssertFailed(t, db, knowledge.SourceGCVE)
	if got := watermark(t, db); !got.IsZero() {
		t.Fatalf("watermark = %v, want none until enrichment succeeds", got)
	}

	serveEnrichment(t, http.StatusOK, enrichedRecord)
	retryStart := time.Now().Truncate(time.Second)
	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if got := bulkDownloads.Load(); got != 2 {
		t.Errorf("bulk downloads = %d, want a second read of the dump for the reconcile", got)
	}
	var rows int
	if err := db.NewSelect().Table("gcve").ColumnExpr("count(*)").Scan(context.Background(), &rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Errorf("rows = %d, want the bulk and the enrichment record", rows)
	}
	if got := watermark(t, db); got.Before(retryStart) {
		t.Errorf("watermark = %v, want the retry's start %v", got, retryStart)
	}
	if got := testhelper.ConfigTime(t, db, "gcve_last"); got.Before(retryStart) {
		t.Errorf("gcve_last = %v, want the retry's start %v", got, retryStart)
	}
	if got := bulkCompletedAt(t, db); !got.IsZero() {
		t.Errorf("bulk_completed_at = %v, want it cleared", got)
	}
	if got := testhelper.UpstreamTotal(t, db, knowledge.SourceGCVE); got == nil || *got != 1 {
		t.Errorf("upstream_total = %v, want the dump's record", got)
	}
	testhelper.AssertSucceededAfter(t, db, knowledge.SourceGCVE, time.Time{})
}

func TestIncrementalRunKeepsTheRecordedUpstreamTotal(t *testing.T) {
	db := setup(t, false)
	serve(t, "[]", record, http.StatusOK)
	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}
	serve(t, "["+enrichedRecord+"]", record, http.StatusOK)

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if got := testhelper.UpstreamTotal(t, db, knowledge.SourceGCVE); got == nil || *got != 1 {
		t.Errorf("upstream_total = %v, want the full import's 1, not the window's count", got)
	}
}

// The upstream total is the dump's distinct records, whether a full import or a bulk fallback read it.
func TestFullImportAndBulkFallbackCountTheDumpAlike(t *testing.T) {
	dump := record + "\n" + record + "\n"
	full := setup(t, false)
	serve(t, "[]", dump, http.StatusOK)
	serveEnrichment(t, http.StatusOK, enrichedRecord)
	if err := Update(full, full); err != nil {
		t.Fatal(err)
	}

	fallback := setup(t, true)
	serve(t, "not json", dump, http.StatusOK)
	if err := Update(fallback, fallback); err != nil {
		t.Fatal(err)
	}

	for name, db := range map[string]*bun.DB{"full import": full, "bulk fallback": fallback} {
		if got := testhelper.UpstreamTotal(t, db, knowledge.SourceGCVE); got == nil || *got != 1 {
			t.Errorf("%s upstream_total = %v, want the dump's 1 distinct record", name, got)
		}
	}
}

func TestRepeatedEnrichmentFailureKeepsSourceFailedAndBulkTime(t *testing.T) {
	stale := time.Now().Add(-40 * 24 * time.Hour).Truncate(time.Second)
	db := setup(t, false)
	testhelper.SeedWatermark(t, db, knowledge.SourceGCVE, stale)
	bulkDownloads := serve(t, "[]", record, http.StatusOK)
	serveEnrichment(t, http.StatusBadGateway, "")

	if err := Update(db, db); err == nil {
		t.Fatal("a failed enrichment should fail the source")
	}
	completedAt := bulkCompletedAt(t, db)
	if completedAt.IsZero() {
		t.Fatal("bulk_completed_at should be set after the bulk import finished")
	}

	if err := Update(db, db); err == nil {
		t.Fatal("a repeated enrichment failure should fail the source")
	}

	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceGCVE, stale)
	if got := bulkCompletedAt(t, db); !got.Equal(completedAt) {
		t.Errorf("bulk_completed_at = %v, want it kept at %v", got, completedAt)
	}
	if got := bulkDownloads.Load(); got != 1 {
		t.Errorf("bulk downloads = %d, want 1", got)
	}
	if !testhelper.ConfigTimeIsNull(t, db, "gcve_last") {
		t.Error("gcve_last should stay unset")
	}
}

func TestBulkParseErrorIsNotBulkDone(t *testing.T) {
	db := setup(t, false)
	bulkDownloads := serve(t, "[]", `{"cveMetadata":"not an object"}`, http.StatusOK)

	if err := Update(db, db); err == nil {
		t.Fatal("an unparsable bulk record should fail the source")
	}
	if got := bulkCompletedAt(t, db); !got.IsZero() {
		t.Errorf("bulk_completed_at = %v, want it unset", got)
	}

	if err := Update(db, db); err == nil {
		t.Fatal("an unparsable bulk record should fail the source")
	}
	if got := bulkDownloads.Load(); got != 2 {
		t.Errorf("bulk downloads = %d, want a fresh download each run", got)
	}
}

func TestRejectedRecordRetiresStoredRowAndDropsLinks(t *testing.T) {
	db := setup(t, true)
	if err := processBatch(db, []knowledge.GCVEItem{{GCVEId: "GCVE-0-2026-0002", CVEId: "CVE-2026-0002", State: "PUBLISHED",
		Affected:          []knowledge.GCVEAffected{{Vendor: "v", Product: "p"}},
		AffectedFlattened: []knowledge.GCVEProduct{{Vendor: "v", Product: "p"}}}}); err != nil {
		t.Fatal(err)
	}
	rejected, err := parseCVERecord([]byte(`{"cveMetadata":{"cveId":"CVE-2026-0002","state":"REJECTED","dateUpdated":"2026-01-02T03:04:05"}}`))
	if err != nil {
		t.Fatal(err)
	}

	if err := processBatch(db, []knowledge.GCVEItem{*rejected}); err != nil {
		t.Fatal(err)
	}

	var item knowledge.GCVEItem
	if err := db.NewSelect().Model(&item).Where("gcve_id = ?", "GCVE-0-2026-0002").Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if item.RetiredReason != knowledge.RetiredRejected || item.RetiredAt.Format(time.RFC3339) != "2026-01-02T03:04:05Z" {
		t.Errorf("got %q at %s", item.RetiredReason, item.RetiredAt)
	}
	if item.State != "PUBLISHED" {
		t.Errorf("State = %q, want PUBLISHED", item.State)
	}
	var links int
	if err := db.NewRaw("SELECT count(*) FROM package_vulnerability WHERE gcve_id = ?", item.Id).Scan(context.Background(), &links); err != nil || links != 0 {
		t.Errorf("links = %d, err %v, want none", links, err)
	}
}
