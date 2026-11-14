package knowledge

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/mirrors/nvd"
	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledgedb "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

const nvdConfigurations = `[{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:vendor:%s:1.0:*:*:*:*:*:*:*"}]}]}]`

// nvdRecord is one CVE as the NVD API returns it, with configurations naming product when set.
func nvdRecord(id, status, lastModified, product string) string {
	configurations := "[]"
	if product != "" {
		configurations = fmt.Sprintf(nvdConfigurations, product)
	}
	return fmt.Sprintf(`{"cve":{"id":%q,"vulnStatus":%q,"published":"2024-01-01T00:00:00.000","lastModified":%q,"descriptions":[{"lang":"en","value":"%s"}],"configurations":%s}}`,
		id, status, lastModified, id, configurations)
}

// fullNVD holds one CVE per status; NVD keeps no configurations on records it has not analyzed.
var fullNVD = []string{
	nvdRecord("CVE-2024-0001", "Analyzed", "2024-02-01T00:00:00.000", "analyzed_product"),
	nvdRecord("CVE-2024-0002", "Modified", "2024-02-02T00:00:00.000", "modified_product"),
	nvdRecord("CVE-2024-0003", "Awaiting Analysis", "2024-02-03T00:00:00.000", ""),
	nvdRecord("CVE-2024-0004", "Deferred", "2024-02-04T00:00:00.000", "deferred_product"),
	nvdRecord("CVE-2024-0005", "Rejected", "2024-03-05T10:30:00.000", "rejected_product"),
}

func init() {
	registerFakeSource(fakeSource{
		name: knowledgedb.SourceNVD,
		createTables: func(t *testing.T, db *bun.DB) {
			testhelper.CreateTables(t, db, (*knowledgedb.NVDItem)(nil))
			if _, err := db.Exec("CREATE UNIQUE INDEX ON nvd (nvd_id)"); err != nil {
				t.Fatal(err)
			}
			// Other advisory sources share the package link table, so create it only once.
			var exists bool
			if err := db.QueryRow("SELECT to_regclass('package_vulnerability') IS NOT NULL").Scan(&exists); err != nil {
				t.Fatal(err)
			}
			if !exists {
				testhelper.CreateTables(t, db, (*knowledgedb.PackageVulnerability)(nil))
				testhelper.CreatePackageLinkIndexes(t, db)
			}
		},
		serve: func(t *testing.T, empty bool) {
			t.Setenv("NVD_API_KEY", "test-key")
			records := fullNVD
			if empty {
				records = nil
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintf(w, `{"totalResults":%d,"vulnerabilities":[%s]}`, len(records), strings.Join(records, ","))
			}))
			t.Cleanup(server.Close)
			t.Cleanup(nvd.UseUpstream(server.URL))
		},
		upstreamTotal: int64(len(fullNVD)),
		breaks: append(upstreamTotalBreaks(knowledgedb.SourceNVD),
			gateBreak{"nvd analyzed record without configurations", []string{"nvd.configurations"}, func(t *testing.T, b build) {
				b.exec(t, b.knowledge, "UPDATE nvd SET configurations = '[]' WHERE nvd_id = 'CVE-2024-0001'")
			}},
			gateBreak{"nvd modified record with null configurations", []string{"nvd.configurations"}, func(t *testing.T, b build) {
				b.exec(t, b.knowledge, "UPDATE nvd SET configurations = NULL WHERE nvd_id = 'CVE-2024-0002'")
			}},
		),
	})
}

// storedNVD is what a build keeps of one CVE.
type storedNVD struct {
	Status        string     `bun:"vulnStatus"`
	RetiredReason *string    `bun:"retired_reason"`
	RetiredAt     *time.Time `bun:"retired_at"`
	Links         int        `bun:"links"`
}

func readStoredNVD(t *testing.T, db *bun.DB) map[string]storedNVD {
	t.Helper()
	var rows []struct {
		ID string `bun:"nvd_id"`
		storedNVD
	}
	err := db.NewRaw(`SELECT n.nvd_id, n."vulnStatus", n.retired_reason, n.retired_at,
		(SELECT count(*) FROM package_vulnerability p WHERE p.nvd_id = n.id) AS links FROM nvd n`).
		Scan(context.Background(), &rows)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]storedNVD{}
	for _, row := range rows {
		out[row.ID] = row.storedNVD
	}
	return out
}

func TestBuildFromEmptyStoresNVDRejectedAndDeferredRecords(t *testing.T) {
	b := newBuild(t)

	b.mustUpdate(t)

	stored := readStoredNVD(t, b.knowledge)
	if len(stored) != len(fullNVD) {
		t.Fatalf("stored %d NVD records, want every upstream record (%d)", len(stored), len(fullNVD))
	}
	rejected := stored["CVE-2024-0005"]
	wantRejectedAt := time.Date(2024, 3, 5, 10, 30, 0, 0, time.UTC)
	if rejected.RetiredReason == nil || *rejected.RetiredReason != knowledgedb.RetiredRejected {
		t.Errorf("rejected record retired_reason = %v, want %q", rejected.RetiredReason, knowledgedb.RetiredRejected)
	}
	if rejected.RetiredAt == nil || !rejected.RetiredAt.Equal(wantRejectedAt) {
		t.Errorf("rejected record retired_at = %v, want its rejection date %v", rejected.RetiredAt, wantRejectedAt)
	}
	if rejected.Links != 0 {
		t.Errorf("rejected record has %d package links, want none", rejected.Links)
	}
	deferred := stored["CVE-2024-0004"]
	if deferred.Status != "Deferred" || deferred.RetiredReason != nil {
		t.Errorf("deferred record = %+v, want stored active with status Deferred", deferred)
	}
	if deferred.Links != 0 {
		t.Errorf("deferred record has %d package links, want none", deferred.Links)
	}
	if stored["CVE-2024-0001"].Links == 0 {
		t.Error("analyzed record has no package links")
	}
}
