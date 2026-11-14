package nvd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

func setupNoWatermark(t *testing.T) *bun.DB {
	t.Helper()
	db := setup(t)
	if _, err := db.ExecContext(context.Background(), "UPDATE knowledge_source_sync SET watermark = NULL"); err != nil {
		t.Fatal(err)
	}
	return db
}

func record(id, status string) string {
	return fmt.Sprintf(`{"cve":{"id":%q,"vulnStatus":%q,"configurations":[{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}]}]}]}}`, id, status)
}

// serveFull answers full-fetch calls with total and records, ignoring the start index.
func serveFull(t *testing.T, total int, records ...string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("lastModStartDate") != "" {
			t.Errorf("full fetch sent a date window: %s", r.URL.RawQuery)
		}
		fmt.Fprintf(w, `{"totalResults":%d,"vulnerabilities":[%s]}`, total, strings.Join(records, ","))
	}))
	t.Cleanup(server.Close)
	original := fullURLTemplate
	fullURLTemplate = server.URL + "/?resultsPerPage=%d&startIndex=%d"
	t.Cleanup(func() { fullURLTemplate = original })
}

func seed(t *testing.T, db *bun.DB, ids ...string) {
	t.Helper()
	items := make([]knowledge.NVDItem, len(ids))
	for i, id := range ids {
		items[i] = knowledge.NVDItem{NVDId: id, VulnStatus: "Analyzed"}
	}
	if err := pgsql.UpdateNvd(db, items); err != nil {
		t.Fatal(err)
	}
}

func reason(t *testing.T, db *bun.DB, id string) string {
	t.Helper()
	var value *string
	if err := db.NewRaw("SELECT retired_reason FROM nvd WHERE nvd_id = ?", id).Scan(context.Background(), &value); err != nil {
		t.Fatal(err)
	}
	if value == nil {
		return ""
	}
	return *value
}

func TestNoWatermarkFetchesEverythingAndRetiresAbsentRecords(t *testing.T) {
	db := setupNoWatermark(t)
	seed(t, db, "CVE-1", "CVE-GONE")
	serveFull(t, 1, record("CVE-1", "Analyzed"))

	before := time.Now().Truncate(time.Microsecond)
	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if got := reason(t, db, "CVE-GONE"); got != knowledge.RetiredRemoved {
		t.Errorf("absent record = %q, want removed", got)
	}
	if got := reason(t, db, "CVE-1"); got != "" {
		t.Errorf("present record retired: %q", got)
	}
	testhelper.AssertSucceededAfter(t, db, knowledge.SourceNVD, before.Add(-time.Second))
}

// A stored record NVD now marks deferred or rejected is still published, so it is not removed.
func TestRecordsOnlyDeferredOrRejectedUpstreamAreNotRemoved(t *testing.T) {
	db := setupNoWatermark(t)
	seed(t, db, "CVE-KEPT", "CVE-DEFERRED", "CVE-REJECTED")
	serveFull(t, 3, record("CVE-KEPT", "Analyzed"), record("CVE-DEFERRED", "Deferred"), record("CVE-REJECTED", "Rejected"))

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if got := reason(t, db, "CVE-DEFERRED"); got != "" {
		t.Errorf("deferred record retired: %q", got)
	}
	if total := testhelper.UpstreamTotal(t, db, knowledge.SourceNVD); total == nil || *total != 3 {
		t.Errorf("upstream_total = %v, want 3", total)
	}
	if got := reason(t, db, "CVE-REJECTED"); got != knowledge.RetiredRejected {
		t.Errorf("rejected record = %q, want rejected", got)
	}
}

func TestShortFetchRetiresNothingEvenWithTheGuardOpen(t *testing.T) {
	t.Setenv("KNOWLEDGE_RECONCILE_MAX_REMOVAL_PERCENT", "100")
	db := setupNoWatermark(t)
	seed(t, db, "CVE-1", "CVE-2")
	serveFull(t, 2, record("CVE-1", "Analyzed"))

	if err := Update(db, db); err == nil {
		t.Fatal("a short fetch should fail the source")
	}

	if got := reason(t, db, "CVE-2"); got != "" {
		t.Errorf("valid record retired after a short fetch: %q", got)
	}
	testhelper.AssertFailed(t, db, knowledge.SourceNVD)
}

func TestLargeRemovalFailsWithoutRetiring(t *testing.T) {
	db := setupNoWatermark(t)
	var ids []string
	for i := range 40 {
		ids = append(ids, fmt.Sprintf("CVE-%d", i))
	}
	seed(t, db, ids...)
	serveFull(t, 2, record("CVE-0", "Analyzed"), record("CVE-1", "Analyzed"))

	if err := Update(db, db); err == nil {
		t.Fatal("an implausible removal should fail the source")
	}

	if got := reason(t, db, "CVE-5"); got != "" {
		t.Errorf("record retired by a refused reconcile: %q", got)
	}
}

func TestFullFetchStoresAllConfigurations(t *testing.T) {
	db := setupNoWatermark(t)
	serveFull(t, 1, record("CVE-1", "Analyzed"))

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	var item knowledge.NVDItem
	if err := db.NewSelect().Model(&item).Where("nvd_id = ?", "CVE-1").Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(item.Configurations) != 1 {
		t.Errorf("configurations = %d, want 1", len(item.Configurations))
	}
}
