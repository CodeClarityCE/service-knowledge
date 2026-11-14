package epss

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

const header = "#model_version:v2025.03.14,score_date:2026-11-08T12:55:00.000+0000\ncve,epss,percentile\n"

func gzipped(t *testing.T, content string) []byte {
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

func setup(t *testing.T, status int, body []byte) *bun.DB {
	t.Helper()
	db := testhelper.SetupSyncTestDB(t)
	testhelper.CreateTables(t, db, (*knowledge.EPSS)(nil))
	if _, err := db.Exec("CREATE UNIQUE INDEX ON epss (cve)"); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	original := baseURL
	baseURL = server.URL + "/"
	t.Cleanup(func() { baseURL = original })
	return db
}

func storedCVEs(t *testing.T, db *bun.DB) []string {
	t.Helper()
	var cves []string
	if err := db.NewRaw("SELECT cve FROM epss ORDER BY 1").Scan(context.Background(), &cves); err != nil {
		t.Fatal(err)
	}
	return cves
}

func TestCompleteFileScoresDatesAndRemovesAbsentCVEs(t *testing.T) {
	db := setup(t, http.StatusOK, gzipped(t, header+"CVE-2024-1,0.5,0.9\n"))
	if _, err := db.Exec("INSERT INTO epss (cve, score) VALUES ('CVE-2024-1', 0.1), ('CVE-gone', 0.1)"); err != nil {
		t.Fatal(err)
	}

	if err := Update(db); err != nil {
		t.Fatal(err)
	}

	if got := storedCVEs(t, db); len(got) != 1 || got[0] != "CVE-2024-1" {
		t.Errorf("stored = %v, want only CVE-2024-1", got)
	}
	var score float32
	var date string
	if err := db.QueryRow("SELECT score, score_date::text FROM epss").Scan(&score, &date); err != nil {
		t.Fatal(err)
	}
	if score != 0.5 || date != "2026-11-08" {
		t.Errorf("score %v date %s, want 0.5 and 2026-11-08", score, date)
	}
}

func assertUntouched(t *testing.T, db *bun.DB) {
	t.Helper()
	if got := storedCVEs(t, db); len(got) != 2 {
		t.Errorf("stored = %v, want both CVEs kept", got)
	}
}

func seedTwo(t *testing.T, db *bun.DB) {
	t.Helper()
	if _, err := db.Exec("INSERT INTO epss (cve) VALUES ('CVE-1'), ('CVE-2')"); err != nil {
		t.Fatal(err)
	}
}

func TestTruncatedGzipRemovesNothing(t *testing.T) {
	data := gzipped(t, header+strings.Repeat("CVE-2024-1,0.5,0.9\n", 500))
	db := setup(t, http.StatusOK, data[:len(data)/2])
	seedTwo(t, db)

	if err := Update(db); err == nil {
		t.Fatal("a truncated file should fail the source")
	}
	assertUntouched(t, db)
}

func TestMalformedRowRemovesNothing(t *testing.T) {
	db := setup(t, http.StatusOK, gzipped(t, header+"CVE-2024-1,abc,0.9\n"))
	seedTwo(t, db)

	if err := Update(db); err == nil {
		t.Fatal("a malformed row should fail the source")
	}
	assertUntouched(t, db)
}

func TestMissingScoreDateRemovesNothing(t *testing.T) {
	db := setup(t, http.StatusOK, gzipped(t, "cve,epss,percentile\nCVE-2024-1,0.1,0.2\n"))
	seedTwo(t, db)

	if err := Update(db); err == nil {
		t.Fatal("a file with no score date should fail the source")
	}
	assertUntouched(t, db)
}

func TestFailedStatusRemovesNothing(t *testing.T) {
	db := setup(t, http.StatusBadGateway, nil)
	seedTwo(t, db)

	if err := Update(db); err == nil {
		t.Fatal("a failed download should fail the source")
	}
	assertUntouched(t, db)
}

func TestHeaderOnlyFileRemovesNothing(t *testing.T) {
	db := setup(t, http.StatusOK, gzipped(t, header))
	seedTwo(t, db)

	if err := Update(db); err == nil {
		t.Fatal("a file with no scores should fail the source")
	}
	assertUntouched(t, db)
}

func TestDatedImportKeepsCVEsAbsentFromThatFile(t *testing.T) {
	db := setup(t, http.StatusOK, gzipped(t, header+"CVE-2024-1,0.5,0.9\n"))
	var values []string
	for i := range 40 {
		values = append(values, fmt.Sprintf("('CVE-2024-%d')", i+100))
	}
	if _, err := db.Exec("INSERT INTO epss (cve) VALUES " + strings.Join(values, ",")); err != nil {
		t.Fatal(err)
	}

	if err := UpdateAsOf(db, "2024-01-01"); err != nil {
		t.Fatalf("a dated file should not trip the removal guard: %v", err)
	}
	if got := storedCVEs(t, db); len(got) != 41 {
		t.Errorf("stored %d CVEs, want the 40 newer ones kept plus the dated one", len(got))
	}
}
