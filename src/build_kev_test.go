package knowledge

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/CodeClarityCE/service-knowledge/src/mirrors/kev"
	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledgedb "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

func init() {
	registerFakeSource(fakeSource{
		name: knowledgedb.SourceKEV,
		createTables: func(t *testing.T, db *bun.DB) {
			testhelper.CreateKEVTable(t, db)
		},
		serve: func(t *testing.T, empty bool) {
			catalog, err := os.ReadFile("mirrors/kev/testdata/known_exploited_vulnerabilities.json")
			if err != nil {
				t.Fatal(err)
			}
			if empty {
				catalog = []byte(`{"title":"CISA Catalog of Known Exploited Vulnerabilities","count":0,"vulnerabilities":[]}`)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(catalog)
			}))
			t.Cleanup(server.Close)
			t.Cleanup(kev.UseUpstream(server.URL))
		},
		upstreamTotal: 3,
		breaks:        upstreamTotalBreaks(knowledgedb.SourceKEV),
		withoutRows:   nil,
	})
}
