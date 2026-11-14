package knowledge

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CodeClarityCE/service-knowledge/src/mirrors/cwe"
	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledgedb "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

const (
	fullCWECatalog = `<Weakness_Catalog><Weaknesses>
<Weakness ID="79" Name="XSS"></Weakness><Weakness ID="89" Name="SQL Injection"></Weakness><Weakness ID="787" Name="Out-of-bounds Write"></Weakness>
</Weaknesses><Categories><Category ID="1" Name="Web"><Relationships><Has_Member CWE_ID="79"/></Relationships></Category></Categories></Weakness_Catalog>`
	emptyCWECatalog = `<Weakness_Catalog><Weaknesses></Weaknesses></Weakness_Catalog>`
)

func init() {
	registerFakeSource(fakeSource{
		name: knowledgedb.SourceCWE,
		createTables: func(t *testing.T, db *bun.DB) {
			testhelper.CreateTables(t, db, (*knowledgedb.CWEEntry)(nil))
			if _, err := db.Exec("CREATE UNIQUE INDEX ON cwe (cwe_id)"); err != nil {
				t.Fatal(err)
			}
		},
		serve: func(t *testing.T, empty bool) {
			catalog := fullCWECatalog
			if empty {
				catalog = emptyCWECatalog
			}
			archive := zipCatalog(t, catalog)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(archive)
			}))
			t.Cleanup(server.Close)
			t.Cleanup(cwe.UseUpstream(server.URL))
		},
		upstreamTotal: 3,
		breaks:        upstreamTotalBreaks(knowledgedb.SourceCWE),
	})
}

func zipCatalog(t *testing.T, catalog string) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	file, err := writer.Create("cwec.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte(catalog)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
