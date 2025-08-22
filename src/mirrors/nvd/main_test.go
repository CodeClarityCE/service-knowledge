package nvd

import (
	"os"
	"testing"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
)

func TestUpdate(t *testing.T) {
	os.Setenv("NVD_API_KEY", "")
	
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
