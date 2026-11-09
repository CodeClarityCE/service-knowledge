package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

var previous = time.Now().Add(-48 * time.Hour).Truncate(time.Second)

const advisory = `{"id":"GHSA-test","affected":[{"package":{"ecosystem":"npm","name":"left-pad"}}]}`

func setup(t *testing.T, files map[string]string) *bun.DB {
	t.Helper()
	db := testhelper.SetupSyncTestDB(t)
	testhelper.CreateTables(t, db, (*knowledge.OSVItem)(nil), (*knowledge.PackageVulnerability)(nil))
	testhelper.CreatePackageLinkIndexes(t, db)
	if _, err := db.ExecContext(context.Background(), "CREATE UNIQUE INDEX ON osv (osv_id)"); err != nil {
		t.Fatal(err)
	}
	testhelper.SeedWatermark(t, db, knowledge.SourceOSV, previous)

	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for name, content := range files {
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive.Bytes())
	}))
	t.Cleanup(server.Close)
	original := dumpBaseURL
	dumpBaseURL = server.URL + "/"
	t.Cleanup(func() { dumpBaseURL = original })
	return db
}

func TestUnparsableAdvisoryLeavesWatermark(t *testing.T) {
	db := setup(t, map[string]string{"good.json": advisory, "bad.json": "{not json"})

	if err := Update(db, db); err == nil {
		t.Fatal("an unparsable advisory should fail the source")
	}
	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceOSV, previous)
}

func TestPackageLinkFailureLeavesWatermark(t *testing.T) {
	db := setup(t, map[string]string{"good.json": advisory})
	testhelper.DropTable(t, db, "package_vulnerability")

	if err := Update(db, db); err == nil {
		t.Fatal("a failed package link insert should fail the source")
	}
	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceOSV, previous)
}

func TestSuccessAdvancesWatermark(t *testing.T) {
	db := setup(t, map[string]string{"good.json": advisory})

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}
	testhelper.AssertSucceededAfter(t, db, knowledge.SourceOSV, previous)
	if got := testhelper.ConfigTime(t, db, "osv_last"); !got.After(previous) {
		t.Errorf("osv_last = %v, want it advanced", got)
	}
}
