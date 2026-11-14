package cwe

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

const catalog = `<Weakness_Catalog><Weaknesses><Weakness ID="79" Name="XSS"></Weakness><Weakness ID="80" Name="Basic"></Weakness></Weaknesses><Categories></Categories></Weakness_Catalog>`

func zipped(t *testing.T, content string) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	file, err := writer.Create("cwec.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func setup(t *testing.T, status int, body []byte) *bun.DB {
	t.Helper()
	db := testhelper.SetupSyncTestDB(t)
	testhelper.CreateTables(t, db, (*knowledge.CWEEntry)(nil))
	if _, err := db.Exec("CREATE UNIQUE INDEX ON cwe (cwe_id); INSERT INTO cwe (cwe_id, name) VALUES ('79', 'old'), ('999', 'gone')"); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	original := catalogURL
	catalogURL = server.URL
	t.Cleanup(func() { catalogURL = original })
	return db
}

func stored(t *testing.T, db *bun.DB) map[string]string {
	t.Helper()
	rows, err := db.Query("SELECT cwe_id, name FROM cwe")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			t.Fatal(err)
		}
		out[id] = name
	}
	return out
}

func TestCompleteCatalogUpdatesAndRemovesAbsent(t *testing.T) {
	db := setup(t, http.StatusOK, zipped(t, catalog))

	if err := Update(db); err != nil {
		t.Fatal(err)
	}

	got := stored(t, db)
	if len(got) != 2 || got["79"] != "XSS" || got["80"] != "Basic" {
		t.Errorf("stored = %v, want 79 updated, 80 added, 999 removed", got)
	}
}

func TestBadDownloadsRemoveNothing(t *testing.T) {
	full := zipped(t, catalog)
	cases := map[string]struct {
		status int
		body   []byte
	}{
		"failed status": {http.StatusBadGateway, nil},
		"truncated zip": {http.StatusOK, full[:len(full)/2]},
		"bad xml":       {http.StatusOK, zipped(t, "<Weakness_Catalog><Weaknesses>")},
		"empty catalog": {http.StatusOK, zipped(t, "<Weakness_Catalog></Weakness_Catalog>")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			db := setup(t, tc.status, tc.body)

			if err := Update(db); err == nil {
				t.Fatal("expected the source to fail")
			}
			if got := stored(t, db); len(got) != 2 || got["999"] != "gone" {
				t.Errorf("stored = %v, want it unchanged", got)
			}
		})
	}
}
