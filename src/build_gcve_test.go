package knowledge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/mirrors/gcve"
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

// serveGCVE starts a fake vulnerability-lookup serving only the bulk dump and an empty update window.
// A request to any other endpoint fails the test.
func serveGCVE(t *testing.T, dump string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/bulk", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		fmt.Fprint(w, dump)
	})
	mux.HandleFunc("/window", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "[]") })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected GCVE request to %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	t.Cleanup(gcve.UseUpstream(server.URL+"/bulk", server.URL+"/window"))
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
				serveGCVE(t, "")
				return
			}
			serveGCVE(t, fullGCVEDump)
		},
		upstreamTotal: 4,
		breaks:        upstreamTotalBreaks(knowledgedb.SourceGCVE),
	})
}

func TestGCVERejectedRecordsAreStoredRetiredWithoutLinks(t *testing.T) {
	b := newBuild(t)
	serveGCVE(t, fullGCVEDump)

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

func TestGCVEBuildsFromEmptyWithOnlyTheBulkDumpAndWindow(t *testing.T) {
	b := newBuild(t)
	serveGCVE(t, fullGCVEDump)
	before := time.Now().Truncate(time.Second)

	if err := updateSources(b.knowledge, b.config, knowledgedb.SourceGCVE); err != nil {
		t.Fatal(err)
	}

	testhelper.AssertSucceededAfter(t, b.knowledge, knowledgedb.SourceGCVE, before)
	if got := testhelper.UpstreamTotal(t, b.knowledge, knowledgedb.SourceGCVE); got == nil || *got != 4 {
		t.Errorf("upstream_total = %v, want the 4 dump records", got)
	}
}

// gcveWithCISAADP is a published record whose CISA-ADP container adds SSVC decision points and an affected product.
const gcveWithCISAADP = `{"cveMetadata":{"cveId":"CVE-2026-2000","state":"PUBLISHED","dateUpdated":"2026-01-01T00:00:00.000Z"},` +
	`"containers":{"cna":{"affected":[{"vendor":"acme","product":"widget"}]},` +
	`"adp":[{"providerMetadata":{"orgId":"134c704f-9b21-4f2e-91b3-4a467353bcc0","shortName":"CISA-ADP"},` +
	`"title":"CISA ADP Vulnrichment",` +
	`"affected":[{"vendor":"acme","product":"gadget"}],` +
	`"metrics":[{"other":{"type":"ssvc","content":{"id":"CVE-2026-2000","role":"CISA Coordinator","version":"2.0.3",` +
	`"timestamp":"2026-01-02T00:00:00Z","options":[{"Exploitation":"none"},{"Automatable":"no"},{"Technical Impact":"partial"}]}}}]}]}}`

func TestGCVEBulkRecordKeepsItsCISAADPEnrichment(t *testing.T) {
	b := newBuild(t)
	serveGCVE(t, fullGCVEDump+gcveWithCISAADP+"\n")

	if err := updateSources(b.knowledge, b.config, knowledgedb.SourceGCVE); err != nil {
		t.Fatal(err)
	}

	var item knowledgedb.GCVEItem
	if err := b.knowledge.NewSelect().Model(&item).Where("gcve_id = ?", "GCVE-0-2026-2000").Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(item.ADPEnrichments) != 1 {
		t.Fatalf("ADP enrichments = %+v, want the CISA-ADP one", item.ADPEnrichments)
	}
	adp := item.ADPEnrichments[0]
	if adp.ShortName != "CISA-ADP" || adp.Title != "CISA ADP Vulnrichment" {
		t.Errorf("ADP enrichment = %q %q, want CISA-ADP", adp.ShortName, adp.Title)
	}
	if len(adp.Metrics) != 1 || adp.Metrics[0].Other == nil || adp.Metrics[0].Other.Type != "ssvc" {
		t.Fatalf("ADP metrics = %+v, want the SSVC metric", adp.Metrics)
	}
	var ssvc struct {
		Options []map[string]string `json:"options"`
	}
	if err := json.Unmarshal(adp.Metrics[0].Other.Content, &ssvc); err != nil {
		t.Fatal(err)
	}
	if len(ssvc.Options) != 3 || ssvc.Options[0]["Exploitation"] != "none" || ssvc.Options[2]["Technical Impact"] != "partial" {
		t.Errorf("SSVC options = %v, want the three decision points", ssvc.Options)
	}
	var links int
	if err := b.knowledge.NewRaw("SELECT count(*) FROM package_vulnerability WHERE gcve_id = ? AND package_name = 'gadget'", item.Id).Scan(context.Background(), &links); err != nil {
		t.Fatal(err)
	}
	if links != 1 {
		t.Errorf("package links for the ADP-added product = %d, want 1", links)
	}
}
