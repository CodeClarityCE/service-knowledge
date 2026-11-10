package knowledge

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/mirrors/epss"
	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledgedb "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// epssFile is a scores file as EPSS publishes it, scored on the given day.
func epssFile(scoredOn time.Time, rows ...string) string {
	file := "#model_version:v2025.03.14,score_date:" + scoredOn.UTC().Format("2006-01-02") + "T12:55:00.000+0000\ncve,epss,percentile\n"
	for _, row := range rows {
		file += row + "\n"
	}
	return file
}

func init() {
	registerFakeSource(fakeSource{
		name: knowledgedb.SourceEPSS,
		createTables: func(t *testing.T, db *bun.DB) {
			testhelper.CreateTables(t, db, (*knowledgedb.EPSS)(nil))
			if _, err := db.Exec("CREATE UNIQUE INDEX ON epss (cve)"); err != nil {
				t.Fatal(err)
			}
		},
		serve: func(t *testing.T, empty bool) {
			file := epssFile(time.Now(), "CVE-2024-0001,0.1,0.5", "CVE-2024-0002,0.9,0.99", "CVE-2025-0003,0.01,0.1")
			if empty {
				file = epssFile(time.Now())
			}
			archive := gzipEPSSFile(t, file)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(archive)
			}))
			t.Cleanup(server.Close)
			t.Cleanup(epss.UseUpstream(server.URL + "/"))
		},
		upstreamTotal: 3,
		breaks: []gateBreak{
			{"epss score date too old", []string{"epss.score_date"}, func(t *testing.T, b build) {
				b.exec(t, b.knowledge, "UPDATE epss SET score_date = now() - interval '3 days'")
			}},
			{"epss no score date", []string{"epss.score_date"}, func(t *testing.T, b build) {
				b.exec(t, b.knowledge, "UPDATE epss SET score_date = NULL")
			}},
		},
		withoutRows: []string{"epss.score_date"},
	})
}

func TestEPSSScoreAgeComesFromTheEnvironment(t *testing.T) {
	b := newBuild(t)
	b.mustUpdate(t)
	b.exec(t, b.knowledge, "UPDATE epss SET score_date = now() - interval '5 days'")
	if failed := failedChecks(b.gate(t)); !slices.Equal(failed, []string{"epss.score_date"}) {
		t.Fatalf("failed checks = %v, want [epss.score_date]", failed)
	}

	t.Setenv("KNOWLEDGE_GATE_EPSS_MAX_SCORE_AGE_DAYS", "6")

	if failed := failedChecks(b.gate(t)); len(failed) > 0 {
		t.Errorf("failed checks = %v, want none with a relaxed score age", failed)
	}
}

func gzipEPSSFile(t *testing.T, content string) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	if _, err := writer.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
