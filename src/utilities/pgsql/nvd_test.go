package pgsql

import (
	"context"
	"testing"

	"github.com/CodeClarityCE/utility-boilerplates/testdeps"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// Same shape as the nvd table in the knowledge database.
const nvdTestSchema = `
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE nvd (
	id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
	nvd_id varchar NOT NULL,
	"sourceIdentifier" varchar,
	published timestamptz,
	"lastModified" timestamptz,
	"vulnStatus" varchar,
	descriptions jsonb,
	metrics jsonb,
	weaknesses jsonb,
	configurations jsonb,
	"affectedFlattened" jsonb,
	affected jsonb,
	"references" jsonb,
	vlai_score varchar,
	vlai_confidence double precision,
	retired_reason varchar,
	retired_at timestamptz
);
CREATE UNIQUE INDEX nvd_nvd_id_idx ON nvd (nvd_id);
CREATE TABLE package_vulnerability (
	id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
	package_name varchar NOT NULL, package_ecosystem varchar NOT NULL,
	osv_id uuid, nvd_id uuid, friendsofphp_id uuid, gcve_id uuid,
	created_at timestamptz DEFAULT now()
);
CREATE UNIQUE INDEX ON package_vulnerability (package_name, package_ecosystem, osv_id) WHERE osv_id IS NOT NULL;
CREATE UNIQUE INDEX ON package_vulnerability (package_name, package_ecosystem, nvd_id) WHERE nvd_id IS NOT NULL;
CREATE UNIQUE INDEX ON package_vulnerability (package_name, package_ecosystem, gcve_id) WHERE gcve_id IS NOT NULL;`

// setupNvdDB creates a throwaway database holding only the nvd table and drops it after the test.
func setupNvdDB(t *testing.T) *bun.DB {
	t.Helper()
	return setupTestDB(t, nvdTestSchema)
}

// setupTestDB creates a throwaway database holding the given schema and drops it after the test.
func setupTestDB(t *testing.T, schema string) *bun.DB {
	t.Helper()
	db := testdeps.Postgres(t)
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	return db
}

func nvdItem(id, status, lastModified string) knowledge.NVDItem {
	return knowledge.NVDItem{NVDId: id, VulnStatus: status, LastModified: lastModified}
}

func readNvd(t *testing.T, db *bun.DB, id string) knowledge.NVDItem {
	t.Helper()
	var item knowledge.NVDItem
	if err := db.NewSelect().Model(&item).Where("nvd_id = ?", id).Scan(context.Background()); err != nil {
		t.Fatalf("read %s: %v", id, err)
	}
	return item
}

func countNvd(t *testing.T, db *bun.DB) int {
	t.Helper()
	count, err := db.NewSelect().Model((*knowledge.NVDItem)(nil)).Count(context.Background())
	if err != nil {
		t.Fatalf("count nvd: %v", err)
	}
	return count
}

func TestUpdateNvdPageMixingNewAndExistingCves(t *testing.T) {
	db := setupNvdDB(t)

	if err := UpdateNvd(db, []knowledge.NVDItem{nvdItem("CVE-2024-0001", "Awaiting Analysis", "2024-01-01")}); err != nil {
		t.Fatalf("first page: %v", err)
	}
	original := readNvd(t, db, "CVE-2024-0001")

	page := []knowledge.NVDItem{
		nvdItem("CVE-2024-0001", "Analyzed", "2024-06-01"),
		nvdItem("CVE-2024-0002", "Analyzed", "2024-06-02"),
	}
	if err := UpdateNvd(db, page); err != nil {
		t.Fatalf("mixed page: %v", err)
	}

	updated := readNvd(t, db, "CVE-2024-0001")
	if updated.VulnStatus != "Analyzed" || updated.LastModified != "2024-06-01T00:00:00Z" {
		t.Errorf("existing CVE was not updated: status %q, lastModified %q", updated.VulnStatus, updated.LastModified)
	}
	if updated.Id != original.Id {
		t.Errorf("existing CVE changed id from %s to %s, which would orphan its package links", original.Id, updated.Id)
	}
	if added := readNvd(t, db, "CVE-2024-0002"); added.LastModified != "2024-06-02T00:00:00Z" {
		t.Errorf("new CVE lastModified = %q", added.LastModified)
	}
	if got := countNvd(t, db); got != 2 {
		t.Errorf("row count = %d, want 2", got)
	}
}

func TestUpdateNvdKeepsLastCopyOfCveRepeatedInPage(t *testing.T) {
	db := setupNvdDB(t)

	page := []knowledge.NVDItem{
		nvdItem("CVE-2024-0001", "Analyzed", "2024-01-01"),
		nvdItem("CVE-2024-0001", "Modified", "2024-02-01"),
	}
	if err := UpdateNvd(db, page); err != nil {
		t.Fatalf("UpdateNvd: %v", err)
	}

	if got := readNvd(t, db, "CVE-2024-0001"); got.VulnStatus != "Modified" {
		t.Errorf("status = %q, want the last copy's Modified", got.VulnStatus)
	}
}

func TestUpdateNvdStoresPagesOfOnlyRejectedAndDeferredRecords(t *testing.T) {
	db := setupNvdDB(t)

	page := []knowledge.NVDItem{
		nvdItem("CVE-2024-0001", "Rejected", "2024-01-01"),
		nvdItem("CVE-2024-0002", "Deferred", "2024-01-01"),
	}
	if err := UpdateNvd(db, page); err != nil {
		t.Fatalf("UpdateNvd: %v", err)
	}
	if err := UpdateNvd(db, nil); err != nil {
		t.Fatalf("UpdateNvd with no items: %v", err)
	}

	if got := countNvd(t, db); got != 2 {
		t.Errorf("row count = %d, want both records stored", got)
	}
}

func TestUpdateNvdReturnsErrorAndWritesNothingWhenPageFails(t *testing.T) {
	db := setupNvdDB(t)
	if _, err := db.ExecContext(context.Background(),
		`ALTER TABLE nvd ADD CONSTRAINT no_bad_status CHECK ("vulnStatus" <> 'Bad')`); err != nil {
		t.Fatalf("add constraint: %v", err)
	}

	page := []knowledge.NVDItem{
		nvdItem("CVE-2024-0001", "Analyzed", "2024-01-01"),
		nvdItem("CVE-2024-0002", "Bad", "2024-01-01"),
	}
	if err := UpdateNvd(db, page); err == nil {
		t.Fatal("UpdateNvd returned nil for a failing page")
	}

	if got := countNvd(t, db); got != 0 {
		t.Errorf("row count = %d, want 0 after a failed page", got)
	}
}
