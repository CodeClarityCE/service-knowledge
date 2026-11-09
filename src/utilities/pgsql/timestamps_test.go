package pgsql

import (
	"context"
	"testing"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
)

func TestNormalizeTimestamp(t *testing.T) {
	cases := map[string]string{
		"":                               "",
		"2024-06-01T00:00:00Z":           "2024-06-01T00:00:00Z",
		"2024-06-01T02:00:00+02:00":      "2024-06-01T00:00:00Z",
		"2024-06-01T02:00:00+0200":       "2024-06-01T00:00:00Z",
		"2024-06-01T10:15:30.123":        "2024-06-01T10:15:30.123Z",
		"2024-06-01T10:15:30":            "2024-06-01T10:15:30Z",
		"2024-06-01 10:15:30":            "2024-06-01T10:15:30Z",
		"2024-06-01":                     "2024-06-01T00:00:00Z",
		"2026-03-23T05:06:54.289219582Z": "2026-03-23T05:06:54.289219582Z",
	}
	for input, want := range cases {
		got, ok := NormalizeTimestamp(input)
		if !ok || got != want {
			t.Errorf("NormalizeTimestamp(%q) = %q, %v, want %q", input, got, ok, want)
		}
	}
}

func TestNormalizeTimestampRejectsGarbage(t *testing.T) {
	if got, ok := NormalizeTimestamp("not a date"); ok || got != "" {
		t.Errorf("got %q, %v, want empty and false", got, ok)
	}
}

// A session in another time zone must not shift values that carry no offset.
func TestNvdDateWithoutOffsetIsStoredAsUTC(t *testing.T) {
	db := setupNvdDB(t)
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("SET TIME ZONE 'Asia/Tokyo'"); err != nil {
		t.Fatal(err)
	}
	if err := UpdateNvd(db, []knowledge.NVDItem{nvdItem("CVE-2024-1", "Analyzed", "2024-06-01T00:00:00.000")}); err != nil {
		t.Fatal(err)
	}
	var utc string
	err := db.NewRaw(`SELECT to_char("lastModified" AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI') FROM nvd`).Scan(ctx(), &utc)
	if err != nil {
		t.Fatal(err)
	}
	if utc != "2024-06-01 00:00" {
		t.Errorf("stored %s UTC, want 2024-06-01 00:00", utc)
	}
}

func TestBadDateDoesNotFailTheBatch(t *testing.T) {
	db := setupNvdDB(t)
	err := UpdateNvd(db, []knowledge.NVDItem{
		nvdItem("CVE-2024-1", "Analyzed", "not a date"),
		nvdItem("CVE-2024-2", "Analyzed", "2024-06-01T00:00:00.000"),
	})
	if err != nil {
		t.Fatalf("a bad date should not fail the batch: %v", err)
	}
	var rows int
	if err := db.NewRaw(`SELECT count(*) FROM nvd`).Scan(ctx(), &rows); err != nil || rows != 2 {
		t.Errorf("rows = %d, err %v, want 2", rows, err)
	}
}

func ctx() context.Context { return context.Background() }
