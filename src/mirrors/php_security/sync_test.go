package php_security

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

var previous = time.Now().Add(-48 * time.Hour).Truncate(time.Second)

func setup(t *testing.T, handler http.HandlerFunc) *bun.DB {
	t.Helper()
	db := testhelper.SetupSyncTestDB(t)
	testhelper.CreateTables(t, db, (*knowledge.FriendsOfPHPAdvisory)(nil), (*knowledge.PackageVulnerability)(nil))
	testhelper.CreatePackageLinkIndexes(t, db)
	if _, err := db.ExecContext(context.Background(), "CREATE UNIQUE INDEX ON friends_of_php (advisory_id)"); err != nil {
		t.Fatal(err)
	}
	testhelper.SeedWatermark(t, db, knowledge.SourceFriendsOfPHP, previous)

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	original := advisoriesURL
	advisoriesURL = server.URL + "/?"
	t.Cleanup(func() { advisoriesURL = original })
	return db
}

func serveAdvisory(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprint(w, `{"advisories":{"symfony/symfony":[{"advisoryId":"PKSA-1","packageName":"symfony/symfony"}]}}`)
}

func TestFailedBatchLeavesWatermark(t *testing.T) {
	db := setup(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })

	if err := Update(db); err == nil {
		t.Fatal("a failed batch should fail the source")
	}
	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceFriendsOfPHP, previous)
}

func TestPackageLinkFailureLeavesWatermark(t *testing.T) {
	db := setup(t, serveAdvisory)
	testhelper.DropTable(t, db, "package_vulnerability")

	if err := Update(db); err == nil {
		t.Fatal("a failed package link insert should fail the source")
	}
	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceFriendsOfPHP, previous)
}

func TestSuccessAdvancesWatermark(t *testing.T) {
	db := setup(t, serveAdvisory)

	if err := Update(db); err != nil {
		t.Fatal(err)
	}
	testhelper.AssertSucceededAfter(t, db, knowledge.SourceFriendsOfPHP, previous)
}
