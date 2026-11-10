package knowledge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/mirrors/gcve"
	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledgedb "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// gcveRejectedAt is when the fake upstream rejected CVE-2026-1003.
var gcveRejectedAt = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

func gcvePublished(id string) string {
	return fmt.Sprintf(`{"cveMetadata":{"cveId":%q,"state":"PUBLISHED","dateUpdated":"2026-01-01T00:00:00.000Z"},`+
		`"containers":{"cna":{"affected":[{"vendor":"acme","product":"widget"}]}}}`, id)
}

// The full fake dump holds three published records and one rejected record.
var fullGCVEDump = strings.Join([]string{
	gcvePublished("CVE-2026-1000"),
	gcvePublished("CVE-2026-1001"),
	gcvePublished("CVE-2026-1002"),
	fmt.Sprintf(`{"cveMetadata":{"cveId":"CVE-2026-1003","state":"REJECTED","dateUpdated":%q},"containers":{}}`,
		gcveRejectedAt.Format("2006-01-02T15:04:05.000Z")),
}, "\n") + "\n"

// Vulnrichment enriches records the dump already holds.
var fullGCVEEnrichment = gcvePublished("CVE-2026-1000") + "\n"

// serveGCVE starts a fake vulnerability-lookup with the given dump and enrichment, and an empty update window.
func serveGCVE(t *testing.T, dump, enrichment string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/bulk", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		fmt.Fprint(w, dump)
	})
	mux.HandleFunc("/rich", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, enrichment) })
	mux.HandleFunc("/window", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "[]") })
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	t.Cleanup(gcve.UseUpstream(server.URL+"/bulk", server.URL+"/rich", server.URL+"/window"))
}

// createGCVETables creates gcve and, unless another source already did, the package link table.
func createGCVETables(t *testing.T, db *bun.DB) {
	t.Helper()
	testhelper.CreateTables(t, db, (*knowledgedb.GCVEItem)(nil))
	if _, err := db.Exec("CREATE UNIQUE INDEX ON gcve (gcve_id)"); err != nil {
		t.Fatal(err)
	}
	var links *string
	if err := db.QueryRow("SELECT to_regclass('package_vulnerability')::text").Scan(&links); err != nil {
		t.Fatal(err)
	}
	if links == nil {
		testhelper.CreateTables(t, db, (*knowledgedb.PackageVulnerability)(nil))
		testhelper.CreatePackageLinkIndexes(t, db)
	}
}

func init() {
	registerFakeSource(fakeSource{
		name:         knowledgedb.SourceGCVE,
		createTables: createGCVETables,
		serve: func(t *testing.T, empty bool) {
			if empty {
				serveGCVE(t, "", fullGCVEEnrichment)
				return
			}
			serveGCVE(t, fullGCVEDump, fullGCVEEnrichment)
		},
		upstreamTotal: 4,
		breaks:        upstreamTotalBreaks(knowledgedb.SourceGCVE),
	})
}

func TestGCVERejectedRecordsAreStoredRetiredWithoutLinks(t *testing.T) {
	b := newBuild(t)
	serveGCVE(t, fullGCVEDump, fullGCVEEnrichment)

	if err := updateSources(b.knowledge, b.config, knowledgedb.SourceGCVE); err != nil {
		t.Fatal(err)
	}

	var item knowledgedb.GCVEItem
	err := b.knowledge.NewSelect().Model(&item).Where("gcve_id = ?", "GCVE-0-2026-1003").Scan(context.Background())
	if err != nil {
		t.Fatalf("rejected record not stored: %v", err)
	}
	if item.RetiredReason != knowledgedb.RetiredRejected || !item.RetiredAt.Equal(gcveRejectedAt) {
		t.Errorf("rejected record retired as %q at %s, want rejected at %s", item.RetiredReason, item.RetiredAt, gcveRejectedAt)
	}
	var links int
	if err := b.knowledge.NewRaw("SELECT count(*) FROM package_vulnerability WHERE gcve_id = ?", item.Id).Scan(context.Background(), &links); err != nil {
		t.Fatal(err)
	}
	if links != 0 {
		t.Errorf("rejected record has %d package links, want none", links)
	}
	var active int
	if err := b.knowledge.NewRaw("SELECT count(*) FROM gcve WHERE retired_at IS NULL").Scan(context.Background(), &active); err != nil {
		t.Fatal(err)
	}
	if active != 3 {
		t.Errorf("active records = %d, want the 3 published ones", active)
	}
}

func TestGCVEWithAnEmptyVulnrichmentFails(t *testing.T) {
	b := newBuild(t)
	serveGCVE(t, fullGCVEDump, "")

	err := updateSources(b.knowledge, b.config, knowledgedb.SourceGCVE)

	if !errors.Is(err, sourcesync.ErrNoUpstreamRecords) {
		t.Errorf("update = %v, want ErrNoUpstreamRecords", err)
	}
	testhelper.AssertFailed(t, b.knowledge, knowledgedb.SourceGCVE)
	if got := testhelper.UpstreamTotal(t, b.knowledge, knowledgedb.SourceGCVE); got != nil {
		t.Errorf("upstream_total = %d, want none", *got)
	}
}
