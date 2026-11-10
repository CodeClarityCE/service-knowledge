package gcve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

func dated(id string, updated time.Time) string {
	return fmt.Sprintf(`{"cveMetadata":{"cveId":%q,"state":"PUBLISHED","dateUpdated":%q},"containers":{"cna":{"affected":[{"vendor":"v","product":"p"}]}}}`,
		id, updated.UTC().Format("2006-01-02T15:04:05.000Z"))
}

// fakeUpstream behaves like the live window endpoint: ascending, inclusive since, capped pages.
type fakeUpstream struct {
	records      map[string]time.Time
	dump         string
	dumpTime     time.Time
	bulkRequests atomic.Int32
	firstSince   atomic.Value
	queries      atomic.Value
}

func (f *fakeUpstream) window(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.queries.CompareAndSwap(nil, r.URL.RawQuery)
		since, err := time.Parse(time.RFC3339Nano, q.Get("since"))
		if err != nil {
			t.Errorf("bad since %q", q.Get("since"))
		}
		f.firstSince.CompareAndSwap(nil, since)
		ids := make([]string, 0, len(f.records))
		for id, updated := range f.records {
			if !updated.Before(since) {
				ids = append(ids, id)
			}
		}
		sort.Slice(ids, func(a, b int) bool {
			if !f.records[ids[a]].Equal(f.records[ids[b]]) {
				return f.records[ids[a]].Before(f.records[ids[b]])
			}
			return ids[a] < ids[b]
		})
		page, _ := strconv.Atoi(q.Get("page"))
		size, _ := strconv.Atoi(q.Get("per_page"))
		start := min((page-1)*size, len(ids))
		end := min(start+size, len(ids))
		out := make([]json.RawMessage, 0, size)
		for _, id := range ids[start:end] {
			out = append(out, json.RawMessage(dated(id, f.records[id])))
		}
		_ = json.NewEncoder(w).Encode(out)
	}
}

func (f *fakeUpstream) serve(t *testing.T) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/window", f.window(t))
	mux.HandleFunc("/bulk", func(w http.ResponseWriter, _ *http.Request) {
		f.bulkRequests.Add(1)
		if !f.dumpTime.IsZero() {
			w.Header().Set("Last-Modified", f.dumpTime.UTC().Format(http.TimeFormat))
		}
		fmt.Fprint(w, f.dump)
	})
	// Vulnrichment enriches records the dump already holds.
	mux.HandleFunc("/rich", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, f.dump) })
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	originalBulk, originalRich, originalWindow, originalInterval := bulkDumpURL, vulnrichmentURL, vulnerabilityAPI, windowRequestInterval
	bulkDumpURL, vulnrichmentURL, vulnerabilityAPI, windowRequestInterval = server.URL+"/bulk", server.URL+"/rich", server.URL+"/window", 0
	t.Cleanup(func() {
		bulkDumpURL, vulnrichmentURL, vulnerabilityAPI, windowRequestInterval = originalBulk, originalRich, originalWindow, originalInterval
	})
}

func gcveRows(t *testing.T, db *bun.DB) int {
	t.Helper()
	var rows int
	if err := db.NewSelect().Table("gcve").ColumnExpr("count(*)").Scan(context.Background(), &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

func retiredAs(t *testing.T, db *bun.DB, gcveID string) string {
	t.Helper()
	var reason *string
	if err := db.NewRaw("SELECT retired_reason FROM gcve WHERE gcve_id = ?", gcveID).Scan(context.Background(), &reason); err != nil {
		t.Fatal(err)
	}
	if reason == nil {
		return ""
	}
	return *reason
}

func seedRows(t *testing.T, db *bun.DB, ids ...string) {
	t.Helper()
	var items []knowledge.GCVEItem
	for _, id := range ids {
		parsed, err := parseCVERecord([]byte(dated(id, time.Now().Add(-1000*time.Hour))))
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, *parsed)
	}
	if err := processBatch(db, items); err != nil {
		t.Fatal(err)
	}
}

func TestIncrementalReadsEveryRecordOfTheWindow(t *testing.T) {
	db := setup(t, true)
	upstream := &fakeUpstream{records: map[string]time.Time{}}
	base := previous.Add(time.Hour)
	for i := range 250 {
		upstream.records[fmt.Sprintf("CVE-2026-%04d", i)] = base.Add(time.Duration(i) * time.Minute)
	}
	upstream.serve(t)

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if got := gcveRows(t, db); got != 250 {
		t.Errorf("rows = %d, want all 250", got)
	}
	if got := upstream.bulkRequests.Load(); got != 0 {
		t.Errorf("bulk requests = %d, want none", got)
	}
	testhelper.AssertSucceededAfter(t, db, knowledge.SourceGCVE, previous)
	first, _ := upstream.queries.Load().(string)
	if want := "source=cvelistv5"; !containsParam(first, want) {
		t.Errorf("query %q lacks %q", first, want)
	}
	since, _ := upstream.firstSince.Load().(time.Time)
	if since.After(previous) {
		t.Errorf("window starts at %v, after the watermark %v", since, previous)
	}
}

func containsParam(query, param string) bool {
	values, err := parseQuery(query)
	if err != nil {
		return false
	}
	return values[param]
}

func parseQuery(query string) (map[string]bool, error) {
	req, err := http.NewRequest("GET", "http://x/?"+query, nil)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for key, values := range req.URL.Query() {
		for _, value := range values {
			out[key+"="+value] = true
		}
	}
	return out, nil
}

func TestRecordsSharingOneTimestampAreAllRead(t *testing.T) {
	db := setup(t, true)
	upstream := &fakeUpstream{records: map[string]time.Time{}}
	same := previous.Add(time.Hour)
	for i := range 150 {
		upstream.records[fmt.Sprintf("CVE-2026-%04d", i)] = same
	}
	upstream.serve(t)

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if got := gcveRows(t, db); got != 150 {
		t.Errorf("rows = %d, want all 150", got)
	}
}

func TestWindowIgnoredUpstreamFallsBackToBulk(t *testing.T) {
	db := setup(t, true)
	upstream := &fakeUpstream{dump: dated("CVE-2026-9", previous.Add(time.Hour)), dumpTime: previous.Add(2 * time.Hour)}
	upstream.serve(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/window", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "["+dated("CVE-OLD", previous.Add(-90*24*time.Hour))+"]")
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	vulnerabilityAPI = server.URL + "/window"

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if got := upstream.bulkRequests.Load(); got != 1 {
		t.Errorf("bulk requests = %d, want 1", got)
	}
}

func TestFallbackWatermarkIsTheDumpTime(t *testing.T) {
	db := setup(t, true)
	dumpTime := previous.Add(2 * time.Hour).Truncate(time.Second)
	serve(t, "not json", dated("CVE-2026-9", previous.Add(time.Hour)), http.StatusOK)
	fakeDumpTime(t, dumpTime)

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if got := watermark(t, db); !got.Equal(dumpTime) {
		t.Errorf("watermark = %v, want the dump's time %v", got, dumpTime)
	}
}

// A dump older than the watermark cannot cover the window.
func TestStaleDumpFailsInsteadOfAdvancing(t *testing.T) {
	db := setup(t, true)
	bulkDownloads := serve(t, "not json", record, http.StatusOK)
	fakeDumpTime(t, previous.Add(-24*time.Hour))

	if err := Update(db, db); err == nil {
		t.Fatal("a dump older than the watermark should fail the source")
	}

	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceGCVE, previous)
	if got := bulkDownloads.Load(); got != 1 {
		t.Errorf("bulk requests = %d, want the header check only", got)
	}
}

func TestRateLimitedWindowRequestIsRetried(t *testing.T) {
	db := setup(t, true)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, "["+dated("CVE-2026-1", previous.Add(time.Hour))+"]")
	}))
	t.Cleanup(server.Close)
	serve(t, "[]", "", http.StatusOK)
	vulnerabilityAPI = server.URL

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if got := gcveRows(t, db); got != 1 {
		t.Errorf("rows = %d, want 1", got)
	}
}

func TestRecordWithoutACveIdIsRefused(t *testing.T) {
	if _, err := parseCVERecord([]byte(`{"id":"PYSEC-2025-19","modified":"2025-01-01T00:00:00Z"}`)); err == nil {
		t.Fatal("a record with no CVE id should not parse")
	}
}
