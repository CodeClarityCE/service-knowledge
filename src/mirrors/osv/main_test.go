package osv

import (
	"testing"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
)

func TestUpdate(t *testing.T) {
	db, cleanup := testhelper.SetupKnowledgeTestDB(t)
	if db == nil {
		return // Test was skipped
	}
	defer cleanup()

	err := Update(db)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
}
