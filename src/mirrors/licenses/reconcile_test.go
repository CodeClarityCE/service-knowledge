package licenses

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

const list = `{"licenses":[{"licenseId":"MIT","name":"MIT License"}]}`

func setup(t *testing.T, status int, body string) *bun.DB {
	t.Helper()
	db := testhelper.SetupSyncTestDB(t)
	testhelper.CreateTables(t, db, (*knowledge.License)(nil))
	if _, err := db.Exec(`INSERT INTO licenses ("licenseId", "name") VALUES ('MIT', 'old'), ('Gone', 'gone')`); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	original := licensesURL
	licensesURL = server.URL
	t.Cleanup(func() { licensesURL = original })
	return db
}

func ids(t *testing.T, db *bun.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT "licenseId" FROM licenses ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}

func TestCompleteListRemovesAbsentLicenses(t *testing.T) {
	db := setup(t, http.StatusOK, list)

	if err := Update(db); err != nil {
		t.Fatal(err)
	}
	if got := ids(t, db); len(got) != 1 || got[0] != "MIT" {
		t.Errorf("ids = %v, want only MIT", got)
	}
}

func TestBadDownloadsRemoveNothing(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
	}{
		"failed status":  {http.StatusBadGateway, ""},
		"truncated json": {http.StatusOK, list[:len(list)/2]},
		"empty list":     {http.StatusOK, `{"licenses":[]}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			db := setup(t, tc.status, tc.body)

			if err := Update(db); err == nil {
				t.Fatal("expected the source to fail")
			}
			if got := ids(t, db); len(got) != 2 {
				t.Errorf("ids = %v, want both kept", got)
			}
		})
	}
}
