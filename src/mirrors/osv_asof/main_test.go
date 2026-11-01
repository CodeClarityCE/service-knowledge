package osv_asof

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
)

var testAsof = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func loadTestAdvisories(t *testing.T) ([]knowledge.OSVItem, loadStats) {
	t.Helper()
	dir := filepath.Join("testdata", "advisory-db", "advisories", "github-reviewed")
	items, stats, err := loadAdvisories(dir, testAsof)
	if err != nil {
		t.Fatalf("loadAdvisories failed: %v", err)
	}
	return items, stats
}

func TestLoadAdvisoriesFiltering(t *testing.T) {
	items, stats := loadTestAdvisories(t)

	got := map[string]bool{}
	for _, item := range items {
		got[item.OSVId] = true
	}
	want := map[string]bool{"GHSA-px4h-xg32-q955": true, "GHSA-462x-c3jw-vfmw": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("kept advisories = %v, want %v", got, want)
	}

	if stats.kept != 2 {
		t.Errorf("kept = %d, want 2", stats.kept)
	}
	if stats.skippedEcosystem != 1 {
		t.Errorf("skippedEcosystem = %d, want 1 (PyPI-only advisory)", stats.skippedEcosystem)
	}
	if stats.skippedFuture != 1 {
		t.Errorf("skippedFuture = %d, want 1 (advisory published after as-of date)", stats.skippedFuture)
	}
	if stats.skippedInvalid != 0 {
		t.Errorf("skippedInvalid = %d, want 0", stats.skippedInvalid)
	}
}

func TestTransformFieldByField(t *testing.T) {
	items, _ := loadTestAdvisories(t)

	var item *knowledge.OSVItem
	for i := range items {
		if items[i].OSVId == "GHSA-px4h-xg32-q955" {
			item = &items[i]
		}
	}
	if item == nil {
		t.Fatal("GHSA-px4h-xg32-q955 not loaded")
	}

	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"OSVId", item.OSVId, "GHSA-px4h-xg32-q955"},
		{"Schema_version", item.Schema_version, "1.4.0"},
		{"Vlai_score", item.Vlai_score, ""},
		{"Vlai_confidence", item.Vlai_confidence, float64(0)},
		{"Modified", item.Modified, "2023-11-08T04:05:58Z"},
		{"Published", item.Published, "2021-06-07T21:56:34Z"},
		{"Withdrawn", item.Withdrawn, ""},
		{"Aliases", item.Aliases, []string{"CVE-2021-33502"}},
		{"Related", item.Related, []string(nil)},
		{"Summary", item.Summary, "Regular expression denial of service in normalize-url"},
		{"Details", item.Details, "The package normalize-url before 4.5.1 is vulnerable to Regular Expression Denial of Service (ReDoS) via the data URL parsing logic."},
		{"Severity", item.Severity, []knowledge.Severity{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
		}},
		{"Affected", item.Affected, []knowledge.Affected{
			{
				Package:          knowledge.OSVPackage{Ecosystem: "npm", Name: "normalize-url", Purl: "pkg:npm/normalize-url"},
				Ranges:           []knowledge.Range{{Type: "SEMVER", Events: []knowledge.Event{{Introduced: "4.3.0"}, {Fixed: "4.5.1"}}}},
				DatabaseSpecific: map[string]any{"last_known_affected_version_range": "<= 4.5.0"},
			},
			{
				Package:  knowledge.OSVPackage{Ecosystem: "npm", Name: "normalize-url", Purl: "pkg:npm/normalize-url"},
				Ranges:   []knowledge.Range{{Type: "SEMVER", Events: []knowledge.Event{{Introduced: "5.0.0"}, {Fixed: "5.3.1"}}}},
				Versions: []string{"5.0.0", "5.1.0", "5.2.0", "5.3.0"},
			},
		}},
		{"References", item.References, []knowledge.Reference{
			{Type: "ADVISORY", Url: "https://nvd.nist.gov/vuln/detail/CVE-2021-33502"},
			{Type: "PACKAGE", Url: "https://github.com/sindresorhus/normalize-url"},
		}},
		{"Credits", item.Credits, []knowledge.Credit{{Name: "Yeting Li", Type: "REPORTER"}}},
		{"DatabaseSpecific", item.DatabaseSpecific, map[string]any{
			"cwe_ids":            []any{"CWE-1333"},
			"severity":           "HIGH",
			"github_reviewed":    true,
			"github_reviewed_at": "2021-06-04T20:41:32Z",
			"nvd_published_at":   "2021-05-28T18:15:00Z",
		}},
		{"Cwes", item.Cwes, []string{"CWE-1333"}},
		{"Cve", item.Cve, "CVE-2021-33502"},
	}

	for _, check := range checks {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s = %#v, want %#v", check.field, check.got, check.want)
		}
	}
}

func TestWithdrawnAdvisoryKept(t *testing.T) {
	items, _ := loadTestAdvisories(t)

	for _, item := range items {
		if item.OSVId != "GHSA-462x-c3jw-vfmw" {
			continue
		}
		if item.Withdrawn != "2022-04-25T20:20:31Z" {
			t.Errorf("Withdrawn = %q, want %q", item.Withdrawn, "2022-04-25T20:20:31Z")
		}
		if item.Cve != "" {
			t.Errorf("Cve = %q, want empty (no CVE alias)", item.Cve)
		}
		if item.Cwes != nil {
			t.Errorf("Cwes = %#v, want nil (empty cwe_ids)", item.Cwes)
		}
		return
	}
	t.Fatal("withdrawn advisory GHSA-462x-c3jw-vfmw not loaded")
}

func TestInScope(t *testing.T) {
	affected := func(ecosystems ...string) []knowledge.Affected {
		var result []knowledge.Affected
		for _, ecosystem := range ecosystems {
			result = append(result, knowledge.Affected{Package: knowledge.OSVPackage{Ecosystem: ecosystem, Name: "pkg"}})
		}
		return result
	}

	cases := []struct {
		name string
		item knowledge.OSVItem
		want bool
	}{
		{"npm", knowledge.OSVItem{Affected: affected("npm")}, true},
		{"Packagist", knowledge.OSVItem{Affected: affected("Packagist")}, true},
		{"PyPI only", knowledge.OSVItem{Affected: affected("PyPI")}, false},
		{"multi-ecosystem with npm", knowledge.OSVItem{Affected: affected("Maven", "npm")}, true},
		{"no affected", knowledge.OSVItem{}, false},
	}
	for _, c := range cases {
		if got := inScope(c.item); got != c.want {
			t.Errorf("%s: inScope = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPublishedAfter(t *testing.T) {
	cases := []struct {
		name      string
		published string
		want      bool
	}{
		{"before as-of day", "2025-12-31T00:00:00Z", false},
		{"on as-of day", "2026-01-01T23:59:59Z", false},
		{"day after as-of", "2026-01-02T00:00:00Z", true},
		{"far future", "2026-07-15T10:30:00Z", true},
		{"empty", "", false},
		{"unparseable", "not-a-timestamp", false},
	}
	for _, c := range cases {
		item := knowledge.OSVItem{OSVId: "GHSA-test-test-test", Published: c.published}
		if got := publishedAfter(item, testAsof); got != c.want {
			t.Errorf("%s: publishedAfter(%q) = %v, want %v", c.name, c.published, got, c.want)
		}
	}
}

func TestIdsPublishedAfter(t *testing.T) {
	mk := func(published string) knowledge.OSVItem {
		return knowledge.OSVItem{Id: uuid.New(), Published: published}
	}
	kept := []knowledge.OSVItem{
		mk("2025-12-31T23:59:59Z"), // before cutoff
		mk("2026-01-01T12:00:00Z"), // on the asof day (whole day in range)
		mk(""),                     // no timestamp -> kept
		mk("not-a-date"),           // unparseable -> kept
	}
	dropped := []knowledge.OSVItem{
		mk("2026-01-02T00:00:00Z"),
		mk("2026-05-01T08:00:00Z"),
	}

	ids := idsPublishedAfter(append(append([]knowledge.OSVItem{}, kept...), dropped...), testAsof)
	if len(ids) != len(dropped) {
		t.Fatalf("idsPublishedAfter returned %d ids, want %d", len(ids), len(dropped))
	}
	for i, item := range dropped {
		if ids[i] != item.Id {
			t.Errorf("ids[%d] = %s, want %s (input order preserved)", i, ids[i], item.Id)
		}
	}
}
