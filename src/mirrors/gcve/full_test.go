package gcve

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
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
				w.Write(buffer[:n])
			}
			if readErr != nil {
				break
			}
		}
	}))
	t.Cleanup(server.Close)
	bulkDumpURL = server.URL
}

func resetWatermark(t *testing.T, db *bun.DB) {
	t.Helper()
	if err := sourcesync.ResetWatermark(db, knowledge.SourceGCVE); err != nil {
		t.Fatal(err)
	}
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

	if err := Update(db, db); err == nil {
		t.Fatal("an implausible removal should fail the source")
	}

	if got := retiredAs(t, db, "GCVE-0-2026-5"); got != "" {
		t.Errorf("record retired by a refused reconcile: %q", got)
	}
	testhelper.AssertFailed(t, db, knowledge.SourceGCVE)
}

func TestEnrichmentRetryRetiresRecordsAbsentFromTheDump(t *testing.T) {
	db := setup(t, false)
	seedRows(t, db, "CVE-2026-1", "CVE-GONE")
	upstream := &fakeUpstream{dump: dated("CVE-2026-1", time.Now()) + "\n", dumpTime: time.Now()}
	upstream.serve(t)
	serveEnrichment(t, http.StatusBadGateway, "")
	if err := Update(db, db); err == nil {
		t.Fatal("a failed enrichment should fail the source")
	}
	if got := retiredAs(t, db, "GCVE-0-GONE"); got != "" {
		t.Fatalf("record retired before the import finished: %q", got)
	}

	serveEnrichment(t, http.StatusOK, enrichedRecord)
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

func TestEnrichmentRetryStaysFailedWhenTheDumpCannotBeRead(t *testing.T) {
	db := setup(t, false)
	seedRows(t, db, "CVE-2026-1", "CVE-GONE")
	upstream := &fakeUpstream{dump: dated("CVE-2026-1", time.Now()) + "\n", dumpTime: time.Now()}
	upstream.serve(t)
	serveEnrichment(t, http.StatusBadGateway, "")
	if err := Update(db, db); err == nil {
		t.Fatal("a failed enrichment should fail the source")
	}

	serveEnrichment(t, http.StatusOK, enrichedRecord)
	unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(unavailable.Close)
	bulkDumpURL = unavailable.URL
	if err := Update(db, db); err == nil {
		t.Fatal("a retry that cannot reconcile should fail the source")
	}

	testhelper.AssertFailed(t, db, knowledge.SourceGCVE)
	if got := watermark(t, db); !got.IsZero() {
		t.Errorf("watermark = %v, want none until the reconcile has happened", got)
	}
	if got := retiredAs(t, db, "GCVE-0-GONE"); got != "" {
		t.Errorf("record retired without a reconcile: %q", got)
	}
}
