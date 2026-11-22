package osv

import (
	"errors"
	"testing"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
)

func TestImportEcosystemsReportsFailureAfterTryingAll(t *testing.T) {
	tried := []string{}
	err := importEcosystems([]string{"Packagist", "npm"}, func(ecosystem string) error {
		tried = append(tried, ecosystem)
		if ecosystem == "Packagist" {
			return errors.New("download failed")
		}
		return nil
	})
	if err == nil {
		t.Fatal("a failed ecosystem should be reported")
	}
	if len(tried) != 2 {
		t.Errorf("tried %v, want both ecosystems", tried)
	}
}

func TestImportEcosystemsSucceedsWhenAllSucceed(t *testing.T) {
	if err := importEcosystems([]string{"npm"}, func(string) error { return nil }); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParseAdvisorySetsAdvisoryKind(t *testing.T) {
	cases := map[string]string{
		"MAL-2024-1":          knowledge.AdvisoryKindMalicious,
		"GHSA-xxxx-yyyy-zzzz": knowledge.AdvisoryKindVulnerability,
		"PYSEC-2024-1":        knowledge.AdvisoryKindVulnerability,
	}
	for id, want := range cases {
		item, err := ParseAdvisory([]byte(`{"id":"` + id + `"}`))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if item.Kind != want {
			t.Errorf("%s: Kind = %q, want %q", id, item.Kind, want)
		}
	}
}
