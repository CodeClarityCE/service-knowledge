package knowledge

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CodeClarityCE/service-knowledge/src/mirrors/osv"
	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledgedb "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// fullOSVArchives holds, per ecosystem, the advisories its all.zip offers:
// two vulnerabilities, one malicious package advisory and one withdrawn advisory.
var fullOSVArchives = map[string]map[string]string{
	"npm": {
		"GHSA-npm-1.json": `{"id":"GHSA-npm-1","aliases":["CVE-2024-0001"],"affected":[{"package":{"ecosystem":"npm","name":"left-pad"}}]}`,
		"MAL-2024-1.json": `{"id":"MAL-2024-1","affected":[{"package":{"ecosystem":"npm","name":"evil-pkg"}}]}`,
		"GHSA-npm-2.json": `{"id":"GHSA-npm-2","withdrawn":"2024-02-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"right-pad"}}]}`,
	},
	"Packagist": {
		"GHSA-php-1.json": `{"id":"GHSA-php-1","affected":[{"package":{"ecosystem":"Packagist","name":"symfony/http-kernel"}}]}`,
	},
}

func init() {
	registerFakeSource(fakeSource{
		name: knowledgedb.SourceOSV,
		createTables: func(t *testing.T, db *bun.DB) {
			testhelper.CreateTables(t, db, (*knowledgedb.OSVItem)(nil), (*knowledgedb.PackageVulnerability)(nil))
			testhelper.CreatePackageLinkIndexes(t, db)
			if _, err := db.Exec("CREATE UNIQUE INDEX ON osv (osv_id)"); err != nil {
				t.Fatal(err)
			}
		},
		serve: func(t *testing.T, empty bool) {
			archives := map[string][]byte{}
			for _, ecosystem := range osv.ImportedEcosystems {
				files := fullOSVArchives[ecosystem]
				if empty {
					files = nil
				}
				archives["/"+ecosystem+"/all.zip"] = zipOSVArchive(t, files)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				archive, ok := archives[r.URL.Path]
				if !ok {
					http.NotFound(w, r)
					return
				}
				_, _ = w.Write(archive)
			}))
			t.Cleanup(server.Close)
			t.Cleanup(osv.UseUpstream(server.URL + "/"))
		},
		upstreamTotal: 4,
		breaks: append(upstreamTotalBreaks(knowledgedb.SourceOSV),
			gateBreak{"osv has no npm links", []string{"osv.links.npm"}, func(t *testing.T, b build) {
				b.exec(t, b.knowledge, "DELETE FROM package_vulnerability WHERE package_ecosystem = 'npm' AND osv_id IS NOT NULL")
			}},
			gateBreak{"osv has no packagist links", []string{"osv.links.packagist"}, func(t *testing.T, b build) {
				b.exec(t, b.knowledge, "DELETE FROM package_vulnerability WHERE package_ecosystem = 'packagist' AND osv_id IS NOT NULL")
			}},
			gateBreak{"osv npm links only to malicious advisories", []string{"osv.links.npm"}, func(t *testing.T, b build) {
				b.exec(t, b.knowledge, `DELETE FROM package_vulnerability WHERE package_ecosystem = 'npm'
					AND osv_id IN (SELECT id FROM osv WHERE kind = 'vulnerability')`)
			}},
		),
		withoutRows: []string{"osv.links.npm", "osv.links.packagist"},
	})
}

func TestGateReportsMaliciousOSVAdvisoriesSeparately(t *testing.T) {
	b := newBuild(t)
	b.mustUpdate(t)

	checks := map[string]string{}
	for _, check := range b.gate(t).Checks {
		checks[check.Name] = fmt.Sprint(check.Actual)
	}

	// Active vulnerabilities only; the withdrawn and malicious advisories are not counted.
	if got := checks["osv.rows"]; got != "2" {
		t.Errorf("osv.rows actual = %s, want 2", got)
	}
	if got, ok := checks["osv.malicious"]; !ok || got != "1" {
		t.Errorf("osv.malicious actual = %q (reported %v), want 1", got, ok)
	}
}

func zipOSVArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	for name, content := range files {
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
