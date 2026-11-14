package knowledge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CodeClarityCE/service-knowledge/src/mirrors/licenses"
	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledgedb "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

const (
	fullLicenseList = `{"licenses":[
{"licenseId":"MIT","name":"MIT License"},
{"licenseId":"Apache-2.0","name":"Apache License 2.0"},
{"licenseId":"GPL-3.0-only","name":"GNU General Public License v3.0 only"},
{"licenseId":"BSD-3-Clause","name":"BSD 3-Clause License"}]}`
	emptyLicenseList = `{"licenses":[]}`
)

func init() {
	registerFakeSource(fakeSource{
		name: knowledgedb.SourceLicenses,
		createTables: func(t *testing.T, db *bun.DB) {
			testhelper.CreateTables(t, db, (*knowledgedb.License)(nil))
		},
		serve: func(t *testing.T, empty bool) {
			list := fullLicenseList
			if empty {
				list = emptyLicenseList
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(list))
			}))
			t.Cleanup(server.Close)
			t.Cleanup(licenses.UseUpstream(server.URL))
		},
		upstreamTotal: 4,
		breaks:        upstreamTotalBreaks(knowledgedb.SourceLicenses),
	})
}
