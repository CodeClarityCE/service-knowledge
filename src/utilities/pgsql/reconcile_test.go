package pgsql

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

const reconcileLinkSchema = `
CREATE TABLE gcve (
	id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
	gcve_id varchar NOT NULL UNIQUE, cve_id varchar, data_version varchar, state varchar,
	date_published timestamptz, date_updated timestamptz, assigner_org_id varchar,
	descriptions jsonb, affected jsonb, affected_flattened jsonb, metrics jsonb,
	problem_types jsonb, "references" jsonb, adp_enrichments jsonb, cwes text[],
	vlai_score varchar, vlai_confidence double precision,
	retired_reason varchar, retired_at timestamptz
);
CREATE TABLE cwe (id uuid PRIMARY KEY DEFAULT uuid_generate_v4(), cwe_id varchar UNIQUE NOT NULL);
CREATE TABLE licenses (id uuid PRIMARY KEY DEFAULT uuid_generate_v4(), "licenseId" varchar UNIQUE NOT NULL);`

func setupReconcileDB(t *testing.T) *bun.DB {
	t.Helper()
	return setupTestDB(t, soundTypesTestSchema+nvdTestSchema[len("\nCREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";"):]+reconcileLinkSchema)
}

func npmAdvisory(id string) knowledge.OSVItem {
	return knowledge.OSVItem{OSVId: id, Affected: []knowledge.Affected{{Package: knowledge.OSVPackage{Ecosystem: "npm", Name: "left-pad"}}}}
}

func seedOsv(t *testing.T, db *bun.DB, items ...knowledge.OSVItem) {
	t.Helper()
	if err := BatchUpdateOsv(db, items); err != nil {
		t.Fatal(err)
	}
}

func seedOsvLink(t *testing.T, db *bun.DB, osvID, pkg string) uuid.UUID {
	t.Helper()
	id := readOsv(t, db, osvID).Id
	if err := BatchInsertOsvPackageVulnerabilities(db, []knowledge.PackageVulnerability{{PackageName: pkg, PackageEcosystem: "npm", OsvId: &id}}); err != nil {
		t.Fatal(err)
	}
	return id
}

func linkCount(t *testing.T, db *bun.DB, column string, id uuid.UUID) int {
	t.Helper()
	var count int
	query := fmt.Sprintf("SELECT count(*) FROM package_vulnerability WHERE %s = ?", column)
	if err := db.NewRaw(query, id).Scan(context.Background(), &count); err != nil {
		t.Fatal(err)
	}
	return count
}

func linkNames(t *testing.T, db *bun.DB, id uuid.UUID) []string {
	t.Helper()
	var names []string
	err := db.NewRaw("SELECT package_name FROM package_vulnerability WHERE osv_id = ? ORDER BY 1", id).Scan(context.Background(), &names)
	if err != nil {
		t.Fatal(err)
	}
	return names
}

var (
	ecosystems = []string{"npm", "Packagist"}
	runAt      = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
)

func TestReconcileOsvRetiresAbsentAdvisoryAndDropsItsLinks(t *testing.T) {
	db := setupReconcileDB(t)
	seedOsv(t, db, npmAdvisory("GHSA-kept"), npmAdvisory("GHSA-gone"))
	keptID := seedOsvLink(t, db, "GHSA-kept", "left-pad")
	goneID := seedOsvLink(t, db, "GHSA-gone", "left-pad")

	if err := ReconcileOsv(db, []string{"GHSA-kept"}, ecosystems, runAt); err != nil {
		t.Fatal(err)
	}

	gone := readOsv(t, db, "GHSA-gone")
	if gone.RetiredReason != knowledge.RetiredRemoved || !gone.RetiredAt.Equal(runAt) {
		t.Errorf("gone = %q at %s, want removed at %s", gone.RetiredReason, gone.RetiredAt, runAt)
	}
	if got := linkCount(t, db, "osv_id", goneID); got != 0 {
		t.Errorf("gone keeps %d links", got)
	}
	if kept := readOsv(t, db, "GHSA-kept"); kept.RetiredReason != "" {
		t.Errorf("kept advisory was retired: %q", kept.RetiredReason)
	}
	if got := linkCount(t, db, "osv_id", keptID); got != 1 {
		t.Errorf("kept has %d links, want 1", got)
	}
}

func TestReconcileOsvKeepsOutOfScopeRowsAndCoversDrupal(t *testing.T) {
	db := setupReconcileDB(t)
	pypi := knowledge.OSVItem{OSVId: "PYPI-1", Affected: []knowledge.Affected{{Package: knowledge.OSVPackage{Ecosystem: "PyPI", Name: "x"}}}}
	drupal := knowledge.OSVItem{OSVId: "DRUPAL-1", Affected: []knowledge.Affected{{Package: knowledge.OSVPackage{Ecosystem: "Packagist:https://packages.drupal.org/8", Name: "x"}}}}
	seedOsv(t, db, npmAdvisory("GHSA-kept"), pypi, drupal)

	if err := ReconcileOsv(db, []string{"GHSA-kept"}, ecosystems, runAt); err != nil {
		t.Fatal(err)
	}

	if got := readOsv(t, db, "PYPI-1").RetiredReason; got != "" {
		t.Errorf("out-of-scope row retired: %q", got)
	}
	if got := readOsv(t, db, "DRUPAL-1").RetiredReason; got != knowledge.RetiredRemoved {
		t.Errorf("Drupal row = %q, want removed", got)
	}
}

func TestReconcileOsvRefusesImplausibleRemoval(t *testing.T) {
	db := setupReconcileDB(t)
	var items []knowledge.OSVItem
	for i := range 100 {
		items = append(items, npmAdvisory(fmt.Sprintf("GHSA-%d", i)))
	}
	seedOsv(t, db, items...)

	err := ReconcileOsv(db, []string{"GHSA-0"}, ecosystems, runAt)
	if !errors.Is(err, ErrImplausibleRemoval) {
		t.Fatalf("err = %v, want ErrImplausibleRemoval", err)
	}
	var retired int
	if err := db.NewRaw("SELECT count(*) FROM osv WHERE retired_reason IS NOT NULL").Scan(context.Background(), &retired); err != nil || retired != 0 {
		t.Errorf("retired %d rows, err %v, want 0", retired, err)
	}
}

func TestReconcileOsvRefusesEmptySnapshot(t *testing.T) {
	db := setupReconcileDB(t)
	seedOsv(t, db, npmAdvisory("GHSA-kept"))

	if err := ReconcileOsv(db, nil, ecosystems, runAt); !errors.Is(err, ErrImplausibleRemoval) {
		t.Fatalf("err = %v, want ErrImplausibleRemoval", err)
	}
}

func TestReconcileOsvKeepsEarlierRetirement(t *testing.T) {
	db := setupReconcileDB(t)
	item := npmAdvisory("GHSA-old")
	item.Withdrawn = "2025-01-02T03:04:05Z"
	seedOsv(t, db, item, npmAdvisory("GHSA-kept"))
	if err := SyncOsvRetirement(db, []string{"GHSA-old"}); err != nil {
		t.Fatal(err)
	}

	if err := ReconcileOsv(db, []string{"GHSA-kept"}, ecosystems, runAt); err != nil {
		t.Fatal(err)
	}

	old := readOsv(t, db, "GHSA-old")
	if old.RetiredReason != knowledge.RetiredWithdrawn || old.RetiredAt.Format(time.RFC3339) != "2025-01-02T03:04:05Z" {
		t.Errorf("retirement changed to %q at %s", old.RetiredReason, old.RetiredAt)
	}
}

func TestWithdrawnAdvisoryIsRetiredWithItsDateAndLosesLinks(t *testing.T) {
	db := setupReconcileDB(t)
	item := npmAdvisory("GHSA-w")
	seedOsv(t, db, item)
	id := seedOsvLink(t, db, "GHSA-w", "left-pad")
	item.Withdrawn = "2025-12-02T15:11:19Z"
	seedOsv(t, db, item)

	if err := SyncOsvRetirement(db, []string{"GHSA-w"}); err != nil {
		t.Fatal(err)
	}

	got := readOsv(t, db, "GHSA-w")
	if got.RetiredReason != knowledge.RetiredWithdrawn || got.RetiredAt.Format(time.RFC3339) != "2025-12-02T15:11:19Z" {
		t.Errorf("got %q at %s", got.RetiredReason, got.RetiredAt)
	}
	if n := linkCount(t, db, "osv_id", id); n != 0 {
		t.Errorf("withdrawn advisory keeps %d links", n)
	}
}

func TestReassertedAdvisoryIsActiveAgain(t *testing.T) {
	db := setupReconcileDB(t)
	seedOsv(t, db, npmAdvisory("GHSA-back"), npmAdvisory("GHSA-kept"))
	if err := ReconcileOsv(db, []string{"GHSA-kept"}, ecosystems, runAt); err != nil {
		t.Fatal(err)
	}

	if err := SyncOsvRetirement(db, []string{"GHSA-back"}); err != nil {
		t.Fatal(err)
	}

	if got := readOsv(t, db, "GHSA-back"); got.RetiredReason != "" || !got.RetiredAt.IsZero() {
		t.Errorf("still retired: %q at %s", got.RetiredReason, got.RetiredAt)
	}
}

func TestPackageLinksAreReplaced(t *testing.T) {
	db := setupReconcileDB(t)
	seedOsv(t, db, npmAdvisory("GHSA-a"))
	id := seedOsvLink(t, db, "GHSA-a", "old-package")

	links := []knowledge.PackageVulnerability{{PackageName: "new-package", PackageEcosystem: "npm", OsvId: &id}}
	if err := ReplaceOsvPackageLinks(db, []uuid.UUID{id}, links); err != nil {
		t.Fatal(err)
	}

	if got := linkNames(t, db, id); len(got) != 1 || got[0] != "new-package" {
		t.Errorf("links = %v, want only new-package", got)
	}
}

func TestRejectedNvdIsRetiredInPlaceAndUnknownIsStoredRetired(t *testing.T) {
	db := setupReconcileDB(t)
	if err := UpdateNvd(db, []knowledge.NVDItem{nvdItem("CVE-2024-1", "Analyzed", "2024-01-01T00:00:00.000")}); err != nil {
		t.Fatal(err)
	}
	ids, err := GetNvdUUIDsByNvdIds(db, []string{"CVE-2024-1"})
	if err != nil {
		t.Fatal(err)
	}
	id := ids["CVE-2024-1"]
	if err := BatchInsertNvdPackageVulnerabilities(db, []knowledge.PackageVulnerability{{PackageName: "x", PackageEcosystem: "nvd", NvdId: &id}}); err != nil {
		t.Fatal(err)
	}

	err = UpdateNvd(db, []knowledge.NVDItem{
		nvdItem("CVE-2024-1", "Rejected", "2024-09-01T00:00:00.000"),
		nvdItem("CVE-2024-2", "Rejected", "2024-09-01T00:00:00.000"),
	})
	if err != nil {
		t.Fatal(err)
	}

	got := readNvd(t, db, "CVE-2024-1")
	if got.RetiredReason != knowledge.RetiredRejected || got.RetiredAt.Format(time.RFC3339) != "2024-09-01T00:00:00Z" {
		t.Errorf("got %q at %s", got.RetiredReason, got.RetiredAt)
	}
	// The content stays as it was while active, so as-of views can still use it.
	if got.VulnStatus != "Analyzed" {
		t.Errorf("VulnStatus = %q, want Analyzed", got.VulnStatus)
	}
	if n := linkCount(t, db, "nvd_id", id); n != 0 {
		t.Errorf("rejected CVE keeps %d links", n)
	}
	if count := countNvd(t, db); count != 2 {
		t.Errorf("rows = %d, the unknown rejected CVE should be stored", count)
	}
	if unknown := readNvd(t, db, "CVE-2024-2"); unknown.RetiredReason != knowledge.RetiredRejected || unknown.RetiredAt.Format(time.RFC3339) != "2024-09-01T00:00:00Z" {
		t.Errorf("unknown rejected CVE = %q at %s, want retired as rejected", unknown.RetiredReason, unknown.RetiredAt)
	}

	if err := UpdateNvd(db, []knowledge.NVDItem{nvdItem("CVE-2024-1", "Modified", "2024-10-01T00:00:00.000")}); err != nil {
		t.Fatal(err)
	}
	if again := readNvd(t, db, "CVE-2024-1"); again.RetiredReason != "" || !again.RetiredAt.IsZero() {
		t.Errorf("re-asserted CVE still retired: %q", again.RetiredReason)
	}
}

func TestStoredRejectedNvdRowsAreRetired(t *testing.T) {
	db := setupReconcileDB(t)
	_, err := db.Exec(`INSERT INTO nvd (nvd_id, "vulnStatus", "lastModified") VALUES ('CVE-1', 'Rejected', '2023-02-03T00:00:00Z'), ('CVE-2', 'Analyzed', NULL)`)
	if err != nil {
		t.Fatal(err)
	}

	if err := RetireStoredRejectedNvd(db); err != nil {
		t.Fatal(err)
	}

	got := readNvd(t, db, "CVE-1")
	if got.RetiredReason != knowledge.RetiredRejected || got.RetiredAt.Format("2006-01-02") != "2023-02-03" {
		t.Errorf("got %q at %s", got.RetiredReason, got.RetiredAt)
	}
	if other := readNvd(t, db, "CVE-2"); other.RetiredReason != "" {
		t.Errorf("active CVE retired: %q", other.RetiredReason)
	}
}

func TestRejectedGcveIsRetiredAndReassertedIsCleared(t *testing.T) {
	db := setupReconcileDB(t)
	live := knowledge.GCVEItem{GCVEId: "GCVE-0-2024-1", CVEId: "CVE-2024-1", State: "PUBLISHED"}
	if err := BatchUpdateGcve(db, []knowledge.GCVEItem{live}); err != nil {
		t.Fatal(err)
	}
	ids, err := GetGcveUUIDsByGcveIds(db, []string{live.GCVEId})
	if err != nil {
		t.Fatal(err)
	}
	id := ids[live.GCVEId]
	if err := BatchInsertGcvePackageVulnerabilities(db, []knowledge.PackageVulnerability{{PackageName: "x", PackageEcosystem: "gcve", GcveId: &id}}); err != nil {
		t.Fatal(err)
	}

	rejected := knowledge.GCVEItem{GCVEId: live.GCVEId, State: "REJECTED", DateUpdated: "2025-05-05T05:05:05Z"}
	if err := RetireRejectedGcve(db, []knowledge.GCVEItem{rejected}); err != nil {
		t.Fatal(err)
	}

	got := readGcve(t, db, live.GCVEId)
	if got.RetiredReason != knowledge.RetiredRejected || got.RetiredAt.Format(time.RFC3339) != "2025-05-05T05:05:05Z" {
		t.Errorf("got %q at %s", got.RetiredReason, got.RetiredAt)
	}
	if got.State != "PUBLISHED" {
		t.Errorf("State = %q, want PUBLISHED", got.State)
	}
	if n := linkCount(t, db, "gcve_id", id); n != 0 {
		t.Errorf("keeps %d links", n)
	}

	if err := BatchUpdateGcve(db, []knowledge.GCVEItem{live}); err != nil {
		t.Fatal(err)
	}
	if again := readGcve(t, db, live.GCVEId); again.RetiredReason != "" {
		t.Errorf("still retired: %q", again.RetiredReason)
	}
}

func readGcve(t *testing.T, db *bun.DB, id string) knowledge.GCVEItem {
	t.Helper()
	var item knowledge.GCVEItem
	if err := db.NewSelect().Model(&item).Where("gcve_id = ?", id).Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	return item
}

func TestReconcileSnapshotTablesDeleteAbsentRows(t *testing.T) {
	db := setupReconcileDB(t)
	if _, err := db.Exec(`
		INSERT INTO epss (cve) VALUES ('CVE-1'), ('CVE-2');
		INSERT INTO cwe (cwe_id) VALUES ('79'), ('80');
		INSERT INTO licenses ("licenseId") VALUES ('MIT'), ('Old');`); err != nil {
		t.Fatal(err)
	}

	if err := ReconcileEPSS(db, []string{"CVE-1"}); err != nil {
		t.Fatal(err)
	}
	if err := ReconcileCWE(db, []string{"79"}); err != nil {
		t.Fatal(err)
	}
	if err := ReconcileLicenses(db, []string{"MIT"}); err != nil {
		t.Fatal(err)
	}

	for table, want := range map[string]string{"epss": "CVE-1", "cwe": "79", "licenses": "MIT"} {
		column := map[string]string{"epss": "cve", "cwe": "cwe_id", "licenses": `"licenseId"`}[table]
		var rows []string
		if err := db.NewRaw(fmt.Sprintf("SELECT %s FROM %s", column, table)).Scan(context.Background(), &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0] != want {
			t.Errorf("%s = %v, want only %s", table, rows, want)
		}
	}
}

func TestReconcileSnapshotTablesRefuseEmptySnapshot(t *testing.T) {
	db := setupReconcileDB(t)
	if _, err := db.Exec(`INSERT INTO cwe (cwe_id) VALUES ('79')`); err != nil {
		t.Fatal(err)
	}
	if err := ReconcileCWE(db, nil); !errors.Is(err, ErrImplausibleRemoval) {
		t.Fatalf("err = %v, want ErrImplausibleRemoval", err)
	}
	var rows int
	if err := db.NewRaw("SELECT count(*) FROM cwe").Scan(context.Background(), &rows); err != nil || rows != 1 {
		t.Errorf("rows = %d, err %v, want 1", rows, err)
	}
}
