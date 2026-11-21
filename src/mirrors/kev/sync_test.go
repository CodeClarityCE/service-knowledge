package kev

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// recordedCatalog is three entries of the CISA catalog of 2026-11-18, with count set to match.
func recordedCatalog(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/known_exploited_vulnerabilities.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// serve points the mirror at a fake upstream answering every request with status and body.
func serve(t *testing.T, status int, body []byte) *bun.DB {
	t.Helper()
	db := testhelper.SetupSyncTestDB(t)
	testhelper.CreateKEVTable(t, db)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	t.Cleanup(UseUpstream(server.URL + "/known_exploited_vulnerabilities.json"))
	return db
}

func storedCVEs(t *testing.T, db *bun.DB) []string {
	t.Helper()
	var cves []string
	if err := db.NewRaw("SELECT cve FROM kev ORDER BY cve").Scan(context.Background(), &cves); err != nil {
		t.Fatal(err)
	}
	return cves
}

func seed(t *testing.T, db *bun.DB, cves ...string) {
	t.Helper()
	for _, cve := range cves {
		if _, err := db.Exec("INSERT INTO kev (cve, date_added) VALUES (?, '2020-01-01')", cve); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRecordedCatalogIsMirroredWithItsWatermark(t *testing.T) {
	db := serve(t, http.StatusOK, recordedCatalog(t))
	before := time.Now()

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if got := storedCVEs(t, db); len(got) != 3 || got[0] != "CVE-2021-44228" || got[1] != "CVE-2023-4966" || got[2] != "CVE-2024-10441" {
		t.Fatalf("stored = %v, want the three catalog CVEs", got)
	}
	var entry knowledge.KEV
	if err := db.NewSelect().Model(&entry).Where("cve = 'CVE-2023-4966'").Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if entry.DateAdded.Format(time.DateOnly) != "2023-10-18" || entry.DueDate == nil || entry.DueDate.Format(time.DateOnly) != "2023-11-08" {
		t.Errorf("dates = %v, %v, want added 2023-10-18, due 2023-11-08", entry.DateAdded, entry.DueDate)
	}
	if !entry.KnownRansomwareUse || entry.VendorProject != "Citrix" || len(entry.CWEs) != 1 || entry.CWEs[0] != "CWE-119" {
		t.Errorf("entry = %+v, want Citrix, known ransomware use, CWE-119", entry)
	}
	var unknownUse bool
	if err := db.QueryRow("SELECT known_ransomware_use FROM kev WHERE cve = 'CVE-2024-10441'").Scan(&unknownUse); err != nil || unknownUse {
		t.Errorf("CVE-2024-10441 known_ransomware_use = %v (%v), want false for Unknown", unknownUse, err)
	}

	testhelper.AssertSucceededAfter(t, db, knowledge.SourceKEV, before.Add(-time.Second))
	if got := testhelper.UpstreamTotal(t, db, knowledge.SourceKEV); got == nil || *got != 3 {
		t.Errorf("upstream_total = %v, want 3", got)
	}
	if last := testhelper.ConfigTime(t, db, "kev_last"); last.Before(before.Add(-time.Second)) {
		t.Errorf("config kev_last = %v, want this sync", last)
	}
}

func TestEntriesTheCatalogDropsAreRemoved(t *testing.T) {
	db := serve(t, http.StatusOK, recordedCatalog(t))
	seed(t, db, "CVE-2021-44228", "CVE-2020-0001")

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if got := storedCVEs(t, db); len(got) != 3 || got[0] != "CVE-2021-44228" {
		t.Errorf("stored = %v, want the catalog only", got)
	}
}

// assertFailedAndUntouched checks a failed sync kept the watermark, kev_last and the stored entries.
func assertFailedAndUntouched(t *testing.T, db *bun.DB, watermark time.Time) {
	t.Helper()
	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceKEV, watermark)
	if !testhelper.ConfigTimeIsNull(t, db, "kev_last") {
		t.Error("a failed sync wrote config kev_last")
	}
	if got := storedCVEs(t, db); len(got) != 2 {
		t.Errorf("stored = %v, want both seeded entries kept", got)
	}
}

func TestUnavailableCatalogKeepsTheMirror(t *testing.T) {
	db := serve(t, http.StatusServiceUnavailable, []byte("down"))
	watermark := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	testhelper.SeedWatermark(t, db, knowledge.SourceKEV, watermark)
	seed(t, db, "CVE-2020-0001", "CVE-2020-0002")

	if err := Update(db, db); err == nil {
		t.Fatal("an unavailable catalog should fail the source")
	}
	assertFailedAndUntouched(t, db, watermark)
}

func TestCatalogShorterThanItsCountKeepsTheMirror(t *testing.T) {
	var catalog map[string]any
	if err := json.Unmarshal(recordedCatalog(t), &catalog); err != nil {
		t.Fatal(err)
	}
	catalog["count"] = 1786
	body, _ := json.Marshal(catalog)
	db := serve(t, http.StatusOK, body)
	watermark := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	testhelper.SeedWatermark(t, db, knowledge.SourceKEV, watermark)
	seed(t, db, "CVE-2020-0001", "CVE-2020-0002")

	if err := Update(db, db); err == nil {
		t.Fatal("a truncated catalog should fail the source")
	}
	assertFailedAndUntouched(t, db, watermark)
}

func TestEntryWithoutACVEKeepsTheMirror(t *testing.T) {
	var catalog map[string]any
	if err := json.Unmarshal(recordedCatalog(t), &catalog); err != nil {
		t.Fatal(err)
	}
	catalog["vulnerabilities"].([]any)[0].(map[string]any)["cveID"] = ""
	body, _ := json.Marshal(catalog)
	db := serve(t, http.StatusOK, body)
	watermark := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	testhelper.SeedWatermark(t, db, knowledge.SourceKEV, watermark)
	seed(t, db, "CVE-2020-0001", "CVE-2020-0002")

	if err := Update(db, db); err == nil {
		t.Fatal("an entry without a CVE should fail the source")
	}
	assertFailedAndUntouched(t, db, watermark)
}
