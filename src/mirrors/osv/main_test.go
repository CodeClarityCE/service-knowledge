package osv

import (
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
