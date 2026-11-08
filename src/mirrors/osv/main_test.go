package osv

import (
	"errors"
	"testing"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
)

func TestUpdate(t *testing.T) {
	db_knowledge, db_config, cleanup := testhelper.SetupKnowledgeAndConfigTestDB(t)
	if db_knowledge == nil {
		return // Test was skipped
	}
	defer cleanup()

	err := Update(db_knowledge, db_config)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
}

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
