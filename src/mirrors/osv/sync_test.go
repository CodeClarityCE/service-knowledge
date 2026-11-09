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

func osvRow(t *testing.T, db *bun.DB, id string) knowledge.OSVItem {
	t.Helper()
	var item knowledge.OSVItem
	if err := db.NewSelect().Model(&item).Where("osv_id = ?", id).Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	return item
}

func seedStored(t *testing.T, db *bun.DB, id string) {
	t.Helper()
	item := knowledge.OSVItem{OSVId: id, Affected: []knowledge.Affected{{Package: knowledge.OSVPackage{Ecosystem: "npm", Name: "left-pad"}}}}
	if err := InsertBatch(db, []knowledge.OSVItem{item}, "npm"); err != nil {
		t.Fatal(err)
	}
}

func assertNotRetired(t *testing.T, db *bun.DB, id string) {
	t.Helper()
	if got := osvRow(t, db, id); got.RetiredReason != "" {
		t.Errorf("%s retired as %q after a bad download", id, got.RetiredReason)
	}
}

func TestCompleteDownloadRetiresAbsentAdvisory(t *testing.T) {
	db := setup(t, map[string]string{"good.json": advisory})
	seedStored(t, db, "GHSA-gone")

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if got := osvRow(t, db, "GHSA-gone"); got.RetiredReason != knowledge.RetiredRemoved {
		t.Errorf("reason = %q, want removed", got.RetiredReason)
	}
	assertNotRetired(t, db, "GHSA-test")
}

func TestFailedDownloadStatusRetiresNothing(t *testing.T) {
	db := setup(t, map[string]string{"good.json": advisory})
	seedStored(t, db, "GHSA-stored")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)
	dumpBaseURL = server.URL + "/"

	if err := Update(db, db); err == nil {
		t.Fatal("a failed download should fail the source")
	}
	assertNotRetired(t, db, "GHSA-stored")
}

func TestTruncatedArchiveRetiresNothing(t *testing.T) {
	db := setup(t, map[string]string{"good.json": advisory})
	seedStored(t, db, "GHSA-stored")
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	file, _ := writer.Create("good.json")
	_, _ = file.Write([]byte(advisory))
	_ = writer.Close()
	truncated := archive.Bytes()[:archive.Len()/2]
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(truncated)
	}))
	t.Cleanup(server.Close)
	dumpBaseURL = server.URL + "/"

	if err := Update(db, db); err == nil {
		t.Fatal("a truncated archive should fail the source")
	}
	assertNotRetired(t, db, "GHSA-stored")
}

func TestUnparsableAdvisoryRetiresNothing(t *testing.T) {
	db := setup(t, map[string]string{"good.json": advisory, "bad.json": "{not json"})
	seedStored(t, db, "GHSA-stored")

	if err := Update(db, db); err == nil {
		t.Fatal("expected a failure")
	}
	assertNotRetired(t, db, "GHSA-stored")
}

func TestEmptyArchiveRetiresNothing(t *testing.T) {
	db := setup(t, map[string]string{})
	seedStored(t, db, "GHSA-stored")

	if err := Update(db, db); err == nil {
		t.Fatal("an empty archive should fail the source")
	}
	assertNotRetired(t, db, "GHSA-stored")
}

func TestStoreFailureRetiresNothing(t *testing.T) {
	db := setup(t, map[string]string{"good.json": advisory})
	seedStored(t, db, "GHSA-stored")
	// Package links fail to write for this run, so the import is incomplete.
	if _, err := db.ExecContext(context.Background(), "ALTER TABLE package_vulnerability RENAME TO pv_hidden"); err != nil {
		t.Fatal(err)
	}

	updateErr := Update(db, db)

	if _, err := db.ExecContext(context.Background(), "ALTER TABLE pv_hidden RENAME TO package_vulnerability"); err != nil {
		t.Fatal(err)
	}
	if updateErr == nil {
		t.Fatal("a failed link write should fail the source")
	}
	assertNotRetired(t, db, "GHSA-stored")
}

func TestWithdrawnAdvisoryInDumpIsRetiredWithoutLinks(t *testing.T) {
	withdrawn := `{"id":"GHSA-w","withdrawn":"2025-12-02T15:11:19Z","affected":[{"package":{"ecosystem":"npm","name":"left-pad"}}]}`
	db := setup(t, map[string]string{"good.json": advisory, "w.json": withdrawn})

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	got := osvRow(t, db, "GHSA-w")
	if got.RetiredReason != knowledge.RetiredWithdrawn || got.RetiredAt.Format(time.RFC3339) != "2025-12-02T15:11:19Z" {
		t.Errorf("got %q at %s", got.RetiredReason, got.RetiredAt)
	}
	var links int
	err := db.NewRaw("SELECT count(*) FROM package_vulnerability WHERE osv_id = ?", got.Id).Scan(context.Background(), &links)
	if err != nil || links != 0 {
		t.Errorf("links = %d, err %v, want none", links, err)
	}
}

func TestChangedAffectedPackagesReplaceLinks(t *testing.T) {
	db := setup(t, map[string]string{"good.json": advisory})
	first := knowledge.OSVItem{OSVId: "GHSA-test", Affected: []knowledge.Affected{{Package: knowledge.OSVPackage{Ecosystem: "npm", Name: "old-package"}}}}
	if err := InsertBatch(db, []knowledge.OSVItem{first}, "npm"); err != nil {
		t.Fatal(err)
	}

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	var names []string
	err := db.NewRaw("SELECT package_name FROM package_vulnerability").Scan(context.Background(), &names)
	if err != nil || len(names) != 1 || names[0] != "left-pad" {
		t.Errorf("links = %v, err %v, want only left-pad", names, err)
	}
}

func TestDrupalEcosystemLinksAsPackagist(t *testing.T) {
	if got := mapOSVEcosystem("Packagist:https://packages.drupal.org/8"); got != "packagist" {
		t.Errorf("got %q, want packagist", got)
	}
}
