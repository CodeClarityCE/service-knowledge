package nvd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

var previous = time.Now().Add(-48 * time.Hour).Truncate(time.Second)

const cve = `{"cve":{"id":"CVE-2026-0001","vulnStatus":"Analyzed","configurations":[{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}]}]}]}}`

func setup(t *testing.T) *bun.DB {
	t.Helper()
	t.Setenv("NVD_API_KEY", "test-key")
	fastRetries(t)
	db := testhelper.SetupSyncTestDB(t)
	testhelper.CreateTables(t, db, (*knowledge.NVDItem)(nil), (*knowledge.PackageVulnerability)(nil))
	testhelper.CreatePackageLinkIndexes(t, db)
	if _, err := db.ExecContext(context.Background(), "CREATE UNIQUE INDEX ON nvd (nvd_id)"); err != nil {
		t.Fatal(err)
	}
	testhelper.SeedWatermark(t, db, knowledge.SourceNVD, previous)
	return db
}

// serveNVD answers API calls, passing each one's start index to page.
func serveNVD(t *testing.T, page func(w http.ResponseWriter, start int)) {
	t.Helper()
	serveRequests(t, func(w http.ResponseWriter, r *http.Request) {
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		page(w, start)
	})
}

// serveRequests answers NVD API calls, with or without a date window, with handler.
func serveRequests(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	t.Cleanup(UseUpstream(server.URL))
}

func goodPage(total int) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		fmt.Fprintf(w, `{"totalResults":%d,"vulnerabilities":[%s]}`, total, cve)
	}
}

func TestPageFailureLeavesWatermark(t *testing.T) {
	db := setup(t)
	good := goodPage(2001)
	serveNVD(t, func(w http.ResponseWriter, start int) {
		if start == 2000 {
			http.Error(w, "nope", http.StatusBadGateway)
			return
		}
		good(w)
	})

	if err := Update(db, db); err == nil {
		t.Fatal("a failed page should fail the source")
	}
	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceNVD, previous)
}

func TestFailedLaterWindowLeavesWatermarkAndConfig(t *testing.T) {
	db := setup(t)
	old := previous.AddDate(0, 0, -200)
	if _, err := db.ExecContext(context.Background(), "UPDATE knowledge_source_sync SET watermark = ?", old); err != nil {
		t.Fatal(err)
	}
	firstWindow := old.UTC().Format("2006-01-02T15:04:05.000Z")
	good := goodPage(1)
	serveRequests(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("lastModStartDate") != firstWindow {
			http.Error(w, "nope", http.StatusBadGateway)
			return
		}
		good(w)
	})

	if err := Update(db, db); err == nil {
		t.Fatal("a failed later window should fail the source")
	}
	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceNVD, old)
	if !testhelper.ConfigTimeIsNull(t, db, "nvd_last") {
		t.Error("nvd_last should stay unset after a failed run")
	}
}

func TestUpsertFailureLeavesWatermark(t *testing.T) {
	db := setup(t)
	testhelper.DropTable(t, db, "nvd")
	good := goodPage(1)
	serveNVD(t, func(w http.ResponseWriter, _ int) { good(w) })

	if err := Update(db, db); err == nil {
		t.Fatal("a failed upsert should fail the source")
	}
	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceNVD, previous)
}

func TestPackageLinkFailureLeavesWatermark(t *testing.T) {
	db := setup(t)
	testhelper.DropTable(t, db, "package_vulnerability")
	good := goodPage(1)
	serveNVD(t, func(w http.ResponseWriter, _ int) { good(w) })

	if err := Update(db, db); err == nil {
		t.Fatal("a failed package link insert should fail the source")
	}
	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceNVD, previous)
}

func TestSuccessAdvancesWatermarkWithoutClobberingConfig(t *testing.T) {
	db := setup(t)
	good := goodPage(1)
	otherWriter := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	serveNVD(t, func(w http.ResponseWriter, _ int) {
		testhelper.SetConfigTime(t, db, "gcve_last", otherWriter)
		good(w)
	})

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}
	testhelper.AssertSucceededAfter(t, db, knowledge.SourceNVD, previous)
	if got := testhelper.ConfigTime(t, db, "gcve_last"); !got.Equal(otherWriter) {
		t.Errorf("gcve_last = %v, want the other writer's %v", got, otherWriter)
	}
	if got := testhelper.ConfigTime(t, db, "nvd_last"); !got.After(previous) {
		t.Errorf("nvd_last = %v, want it advanced", got)
	}
}

func linkCount(t *testing.T, db *bun.DB, id string) int {
	t.Helper()
	var n int
	err := db.QueryRowContext(context.Background(),
		"SELECT count(*) FROM package_vulnerability p JOIN nvd n ON p.nvd_id = n.id WHERE n.nvd_id = ?", id).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// A CVE NVD defers is kept with its new status but loses the package links it had while analyzed.
func TestDeferredRecordIsStoredWithoutPackageLinks(t *testing.T) {
	db := setup(t)
	analyzed := goodPage(1)
	serveNVD(t, func(w http.ResponseWriter, _ int) { analyzed(w) })
	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}
	if linkCount(t, db, "CVE-2026-0001") == 0 {
		t.Fatal("analyzed CVE should have package links")
	}

	serveNVD(t, func(w http.ResponseWriter, _ int) {
		fmt.Fprintf(w, `{"totalResults":1,"vulnerabilities":[%s]}`, record("CVE-2026-0001", "Deferred"))
	})
	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	var status string
	if err := db.NewRaw(`SELECT "vulnStatus" FROM nvd WHERE nvd_id = 'CVE-2026-0001'`).Scan(context.Background(), &status); err != nil {
		t.Fatal(err)
	}
	if status != "Deferred" {
		t.Errorf("status = %q, want Deferred", status)
	}
	if n := linkCount(t, db, "CVE-2026-0001"); n != 0 {
		t.Errorf("deferred CVE keeps %d package links", n)
	}
}

// An incremental run also records NVD's current total, from one request with no date window.
func TestIncrementalRunRecordsTheCurrentUpstreamTotal(t *testing.T) {
	db := setup(t)
	if _, err := db.ExecContext(context.Background(), "UPDATE knowledge_source_sync SET upstream_total = 420000"); err != nil {
		t.Fatal(err)
	}
	good := goodPage(1)
	serveRequests(t, func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("lastModStartDate") != "" {
			good(w)
			return
		}
		if query.Get("resultsPerPage") != "1" {
			t.Errorf("total request asks for %s results per page, want 1", query.Get("resultsPerPage"))
		}
		fmt.Fprint(w, `{"totalResults":421910,"vulnerabilities":[]}`)
	})

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if got := testhelper.UpstreamTotal(t, db, knowledge.SourceNVD); got == nil || *got != 421910 {
		t.Errorf("upstream_total = %v, want the current 421910", got)
	}
}

// A run whose total request fails keeps its watermark, so the next run repeats the window.
func TestFailedTotalRequestFailsTheIncrementalRun(t *testing.T) {
	db := setup(t)
	good := goodPage(1)
	serveRequests(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("lastModStartDate") == "" {
			http.Error(w, "nope", http.StatusBadGateway)
			return
		}
		good(w)
	})

	if err := Update(db, db); err == nil {
		t.Fatal("a failed total request should fail the source")
	}
	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceNVD, previous)
}
