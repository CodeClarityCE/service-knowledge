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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		page(w, start)
	}))
	t.Cleanup(server.Close)
	original := apiURLTemplate
	apiURLTemplate = server.URL + "/?resultsPerPage=%d&startIndex=%d&lastModStartDate=%s&lastModEndDate=%s"
	t.Cleanup(func() { apiURLTemplate = original })
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
