package gcve

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// fakeDumpTime reports dumpTime as the bulk dump's Last-Modified.
func fakeDumpTime(t *testing.T, dumpTime time.Time) {
	t.Helper()
	inner := bulkDumpURL
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", dumpTime.UTC().Format(http.TimeFormat))
		response, err := http.Get(inner)
		if err != nil {
			t.Error(err)
			return
		}
		defer response.Body.Close()
		w.WriteHeader(response.StatusCode)
		buffer := make([]byte, 1<<16)
		for {
			n, readErr := response.Body.Read(buffer)
			if n > 0 {
				_, _ = w.Write(buffer[:n])
			}
			if readErr != nil {
				break
			}
		}
	}))
	t.Cleanup(server.Close)
	bulkDumpURL = server.URL
}

func TestFullImportCoversChangesAfterTheDumpAndRetiresAbsentRecords(t *testing.T) {
	db := setup(t, false)
	seedRows(t, db, "CVE-2026-1", "CVE-GONE", "CVE-2026-LATE")
	dumpTime := time.Now().Add(-30 * 24 * time.Hour).Truncate(time.Second)
	upstream := &fakeUpstream{
		dump:     dated("CVE-2026-1", dumpTime.Add(-time.Hour)) + "\n",
		dumpTime: dumpTime,
		records:  map[string]time.Time{"CVE-2026-LATE": dumpTime.Add(5 * 24 * time.Hour)},
	}
	upstream.serve(t)
	before := time.Now().Truncate(time.Microsecond)

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if got := retiredAs(t, db, "GCVE-0-GONE"); got != knowledge.RetiredRemoved {
		t.Errorf("absent record = %q, want removed", got)
	}
	if got := retiredAs(t, db, "GCVE-0-2026-1"); got != "" {
		t.Errorf("record in the dump retired: %q", got)
	}
	if got := retiredAs(t, db, "GCVE-0-2026-LATE"); got != "" {
		t.Errorf("record newer than the dump retired: %q", got)
	}
	if got := watermark(t, db); got.Before(before) {
		t.Errorf("watermark = %v, want the run's start %v", got, before)
	}
}

func TestDumpWithoutADateFailsAndRetiresNothing(t *testing.T) {
	db := setup(t, false)
	seedRows(t, db, "CVE-2026-1", "CVE-2026-2")
	upstream := &fakeUpstream{dump: dated("CVE-2026-1", time.Now()) + "\n"}
	upstream.serve(t)

	if err := Update(db, db); err == nil {
		t.Fatal("a dump of unknown age should fail the source")
	}

	if got := retiredAs(t, db, "GCVE-0-2026-2"); got != "" {
		t.Errorf("record retired: %q", got)
	}
}

func TestTruncatedDumpRetiresNothingEvenWithTheGuardOpen(t *testing.T) {
	t.Setenv("KNOWLEDGE_RECONCILE_MAX_REMOVAL_PERCENT", "100")
	db := setup(t, false)
	seedRows(t, db, "CVE-2026-1", "CVE-2026-2")
	upstream := &fakeUpstream{
		dump:     dated("CVE-2026-1", time.Now()) + "\n" + `{"cveMetadata":{"cveId":"CVE-20`,
		dumpTime: time.Now(),
	}
	upstream.serve(t)

	if err := Update(db, db); err == nil {
		t.Fatal("a truncated dump should fail the source")
	}

	if got := retiredAs(t, db, "GCVE-0-2026-2"); got != "" {
		t.Errorf("valid record retired after truncation: %q", got)
	}
}

func TestRejectedRecordsInTheDumpAreNotRemoved(t *testing.T) {
	db := setup(t, false)
	seedRows(t, db, "CVE-2026-1", "CVE-2026-2")
	rejected := `{"cveMetadata":{"cveId":"CVE-2026-2","state":"REJECTED"},"containers":{}}`
	upstream := &fakeUpstream{dump: dated("CVE-2026-1", time.Now()) + "\n" + rejected + "\n", dumpTime: time.Now()}
	upstream.serve(t)

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if got := retiredAs(t, db, "GCVE-0-2026-2"); got != knowledge.RetiredRejected {
		t.Errorf("rejected record = %q, want rejected", got)
	}
}

func TestLargeRemovalFailsWithoutRetiring(t *testing.T) {
	db := setup(t, false)
	var ids []string
	for i := range 40 {
		ids = append(ids, fmt.Sprintf("CVE-2026-%d", i))
	}
	seedRows(t, db, ids...)
	upstream := &fakeUpstream{dump: dated("CVE-2026-0", time.Now()) + "\n", dumpTime: time.Now()}
	upstream.serve(t)

	err := Update(db, db)
	if err == nil || !strings.HasPrefix(err.Error(), "gcve: reconcile: ") {
		t.Fatalf("update = %v, want a failure naming the reconcile", err)
	}

	if got := retiredAs(t, db, "GCVE-0-2026-5"); got != "" {
		t.Errorf("record retired by a refused reconcile: %q", got)
	}
	testhelper.AssertFailed(t, db, knowledge.SourceGCVE)
}

func TestCatchUpFailureAfterBulkResumesWithoutReimporting(t *testing.T) {
	db := setup(t, false)
	dumpTime := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	upstream := &fakeUpstream{
		dump:     dated("CVE-2026-1", dumpTime.Add(-time.Hour)) + "\n",
		dumpTime: dumpTime,
		records:  map[string]time.Time{"CVE-2026-LATE": time.Now().Add(-time.Hour)},
	}
	upstream.windowDown.Store(true)
	upstream.serve(t)

	err := Update(db, db)
	if err == nil || !strings.Contains(err.Error(), "catch-up") {
		t.Fatalf("update = %v, want a catch-up failure", err)
	}
	testhelper.AssertFailed(t, db, knowledge.SourceGCVE)
	if got := bulkCompletedAt(t, db); !got.Equal(dumpTime) {
		t.Fatalf("bulk_completed_at = %v, want the dump's date %v", got, dumpTime)
	}
	if got := watermark(t, db); !got.IsZero() {
		t.Fatalf("watermark = %v, want none until catch-up and reconcile succeed", got)
	}

	// A record only the resume's re-read sees shows that the re-read stores nothing.
	upstream.dump += dated("CVE-2026-REREAD", dumpTime.Add(-time.Hour)) + "\n"
	upstream.windowDown.Store(false)
	resumeStart := time.Now().Truncate(time.Second)
	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if got := upstream.bulkRequests.Load(); got != 2 {
		t.Errorf("bulk requests = %d, want the import and one re-read for the reconcile", got)
	}
	if got := gcveRows(t, db); got != 2 {
		t.Errorf("rows = %d, want the bulk record and the caught-up record", got)
	}
	if got := retiredAs(t, db, "GCVE-0-2026-LATE"); got != "" {
		t.Errorf("caught-up record retired: %q", got)
	}
	if got := bulkCompletedAt(t, db); !got.IsZero() {
		t.Errorf("bulk_completed_at = %v, want it cleared", got)
	}
	if got := watermark(t, db); got.Before(resumeStart) {
		t.Errorf("watermark = %v, want the resume's start %v", got, resumeStart)
	}
	if got := testhelper.ConfigTime(t, db, "gcve_last"); got.Before(resumeStart) {
		t.Errorf("gcve_last = %v, want the resume's start %v", got, resumeStart)
	}
	if got := testhelper.UpstreamTotal(t, db, knowledge.SourceGCVE); got == nil || *got != 3 {
		t.Errorf("upstream_total = %v, want the 2 re-read dump records and the caught-up one", got)
	}
	testhelper.AssertSucceededAfter(t, db, knowledge.SourceGCVE, time.Time{})
}

// failCatchUpOnce runs a full import of a one-record dump whose catch-up fails, over stored
// CVE-2026-1 and CVE-GONE, and leaves the update window working for the next run.
func failCatchUpOnce(t *testing.T) *bun.DB {
	t.Helper()
	db := setup(t, false)
	seedRows(t, db, "CVE-2026-1", "CVE-GONE")
	upstream := &fakeUpstream{dump: dated("CVE-2026-1", time.Now()) + "\n", dumpTime: time.Now()}
	upstream.windowDown.Store(true)
	upstream.serve(t)
	if err := Update(db, db); err == nil {
		t.Fatal("a failed catch-up should fail the source")
	}
	if got := retiredAs(t, db, "GCVE-0-GONE"); got != "" {
		t.Fatalf("record retired before the import finished: %q", got)
	}
	upstream.windowDown.Store(false)
	return db
}

func TestResumeRetiresRecordsAbsentFromTheDump(t *testing.T) {
	db := failCatchUpOnce(t)
	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if got := retiredAs(t, db, "GCVE-0-GONE"); got != knowledge.RetiredRemoved {
		t.Errorf("absent record = %q, want removed", got)
	}
	if got := retiredAs(t, db, "GCVE-0-2026-1"); got != "" {
		t.Errorf("record in the dump retired: %q", got)
	}
}

func TestResumeStaysFailedWhenTheDumpCannotBeRead(t *testing.T) {
	db := failCatchUpOnce(t)
	completedAt := bulkCompletedAt(t, db)

	unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(unavailable.Close)
	bulkDumpURL = unavailable.URL
	if err := Update(db, db); err == nil {
		t.Fatal("a resume that cannot reconcile should fail the source")
	}

	testhelper.AssertFailed(t, db, knowledge.SourceGCVE)
	if got := bulkCompletedAt(t, db); completedAt.IsZero() || !got.Equal(completedAt) {
		t.Errorf("bulk_completed_at = %v, want it kept at %v", got, completedAt)
	}
	if got := watermark(t, db); !got.IsZero() {
		t.Errorf("watermark = %v, want none until the reconcile has happened", got)
	}
	if got := retiredAs(t, db, "GCVE-0-GONE"); got != "" {
		t.Errorf("record retired without a reconcile: %q", got)
	}
}

func TestResumeImportsADumpRebuiltAfterTheBulkImport(t *testing.T) {
	db := setup(t, false)
	firstDump := time.Now().Add(-10 * 24 * time.Hour).Truncate(time.Second)
	rebuilt := time.Now().Add(-3 * 24 * time.Hour).Truncate(time.Second)
	lateUpdate := time.Now().Add(-time.Hour).Truncate(time.Millisecond)
	upstream := &fakeUpstream{
		dump:     dated("CVE-2026-1", firstDump.Add(-time.Hour)) + "\n",
		dumpTime: firstDump,
		records:  map[string]time.Time{"CVE-2026-LATE": lateUpdate},
	}
	upstream.windowDown.Store(true)
	upstream.serve(t)
	if err := Update(db, db); err == nil {
		t.Fatal("a failed catch-up should fail the source")
	}

	// CIRCL rebuilt the dump: it adds a record and holds an older version of the late one.
	upstream.dump += dated("CVE-2026-NEW", rebuilt.Add(-time.Hour)) + "\n" +
		dated("CVE-2026-LATE", rebuilt.Add(-time.Hour)) + "\n"
	upstream.dumpTime = rebuilt
	upstream.windowDown.Store(false)
	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if got := retiredAs(t, db, "GCVE-0-2026-NEW"); got != "" {
		t.Errorf("record of the rebuilt dump retired: %q", got)
	}
	if got := gcveRows(t, db); got != 3 {
		t.Errorf("rows = %d, want the rebuilt dump's 3 records stored", got)
	}
	var updated time.Time
	if err := db.NewRaw("SELECT date_updated FROM gcve WHERE gcve_id = ?", "GCVE-0-2026-LATE").Scan(context.Background(), &updated); err != nil {
		t.Fatal(err)
	}
	if !updated.Equal(lateUpdate) {
		t.Errorf("late record updated at %v, want the caught-up version %v", updated, lateUpdate)
	}
	if got := testhelper.UpstreamTotal(t, db, knowledge.SourceGCVE); got == nil || *got != 3 {
		t.Errorf("upstream_total = %v, want the rebuilt dump's 3 distinct records", got)
	}
	if got := upstream.bulkRequests.Load(); got != 2 {
		t.Errorf("bulk requests = %d, want the first import and one read of the rebuilt dump", got)
	}
	testhelper.AssertSucceededAfter(t, db, knowledge.SourceGCVE, time.Time{})
}

func TestResumeRefusesADumpOlderThanTheBulkImport(t *testing.T) {
	db := setup(t, false)
	dumpTime := time.Now().Add(-2 * 24 * time.Hour).Truncate(time.Second)
	upstream := &fakeUpstream{dump: dated("CVE-2026-1", dumpTime.Add(-time.Hour)) + "\n", dumpTime: dumpTime}
	upstream.windowDown.Store(true)
	upstream.serve(t)
	if err := Update(db, db); err == nil {
		t.Fatal("a failed catch-up should fail the source")
	}

	upstream.dumpTime = dumpTime.Add(-24 * time.Hour)
	upstream.windowDown.Store(false)
	if err := Update(db, db); err == nil {
		t.Fatal("a dump older than the bulk import should fail the resume")
	}

	testhelper.AssertFailed(t, db, knowledge.SourceGCVE)
	if got := bulkCompletedAt(t, db); !got.Equal(dumpTime) {
		t.Errorf("bulk_completed_at = %v, want it kept at %v", got, dumpTime)
	}
}
