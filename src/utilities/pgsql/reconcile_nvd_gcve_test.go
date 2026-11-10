package pgsql

import (
	"errors"
	"fmt"
	"testing"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

func seedNvd(t *testing.T, db *bun.DB, ids ...string) {
	t.Helper()
	items := make([]knowledge.NVDItem, len(ids))
	for i, id := range ids {
		items[i] = knowledge.NVDItem{NVDId: id, VulnStatus: "Analyzed"}
	}
	if err := UpdateNvd(db, items); err != nil {
		t.Fatal(err)
	}
}

func seedGcve(t *testing.T, db *bun.DB, ids ...string) {
	t.Helper()
	items := make([]knowledge.GCVEItem, len(ids))
	for i, id := range ids {
		items[i] = knowledge.GCVEItem{GCVEId: id, CVEId: id, State: "PUBLISHED"}
	}
	if err := BatchUpdateGcve(db, items); err != nil {
		t.Fatal(err)
	}
}

func retiredReason(t *testing.T, db *bun.DB, table, column, id string) string {
	t.Helper()
	var reason *string
	err := db.NewRaw("SELECT retired_reason FROM ? WHERE ? = ?", bun.Ident(table), bun.Ident(column), id).Scan(t.Context(), &reason)
	if err != nil {
		t.Fatal(err)
	}
	if reason == nil {
		return ""
	}
	return *reason
}

func TestReconcileNvdRetiresAbsentRecordsAndDropsTheirLinks(t *testing.T) {
	db := setupReconcileDB(t)
	seedNvd(t, db, "CVE-1", "CVE-2")
	uuids, err := GetNvdUUIDsByNvdIds(db, []string{"CVE-1", "CVE-2"})
	if err != nil {
		t.Fatal(err)
	}
	gone, kept := uuids["CVE-2"], uuids["CVE-1"]
	links := []knowledge.PackageVulnerability{
		{PackageName: "a", PackageEcosystem: "nvd", NvdId: &gone},
		{PackageName: "a", PackageEcosystem: "nvd", NvdId: &kept},
	}
	if err := BatchInsertNvdPackageVulnerabilities(db, links); err != nil {
		t.Fatal(err)
	}

	if err := ReconcileNvd(db, []string{"CVE-1"}, runAt); err != nil {
		t.Fatal(err)
	}

	if got := retiredReason(t, db, "nvd", "nvd_id", "CVE-2"); got != knowledge.RetiredRemoved {
		t.Errorf("absent record = %q, want removed", got)
	}
	if got := retiredReason(t, db, "nvd", "nvd_id", "CVE-1"); got != "" {
		t.Errorf("present record was retired: %q", got)
	}
	if got := linkCount(t, db, "nvd_id", gone); got != 0 {
		t.Errorf("retired record keeps %d links", got)
	}
	if got := linkCount(t, db, "nvd_id", kept); got != 1 {
		t.Errorf("kept record has %d links, want 1", got)
	}
}

func TestReconcileGcveRetiresAbsentRecords(t *testing.T) {
	db := setupReconcileDB(t)
	seedGcve(t, db, "GCVE-0-1", "GCVE-0-2")

	if err := ReconcileGcve(db, []string{"GCVE-0-1"}, runAt); err != nil {
		t.Fatal(err)
	}

	if got := retiredReason(t, db, "gcve", "gcve_id", "GCVE-0-2"); got != knowledge.RetiredRemoved {
		t.Errorf("absent record = %q, want removed", got)
	}
}

func TestReconcileNvdAndGcveRefuseImplausibleRemoval(t *testing.T) {
	db := setupReconcileDB(t)
	var nvd, gcve []string
	for i := range 100 {
		nvd = append(nvd, fmt.Sprintf("CVE-%d", i))
		gcve = append(gcve, fmt.Sprintf("GCVE-%d", i))
	}
	seedNvd(t, db, nvd...)
	seedGcve(t, db, gcve...)

	if err := ReconcileNvd(db, []string{"CVE-0"}, runAt); !errors.Is(err, ErrImplausibleRemoval) {
		t.Errorf("NVD err = %v, want ErrImplausibleRemoval", err)
	}
	if err := ReconcileGcve(db, []string{"GCVE-0"}, runAt); !errors.Is(err, ErrImplausibleRemoval) {
		t.Errorf("GCVE err = %v, want ErrImplausibleRemoval", err)
	}
	if got := retiredReason(t, db, "nvd", "nvd_id", "CVE-5"); got != "" {
		t.Errorf("record retired by a refused reconcile: %q", got)
	}
}

func TestReconcileNvdLeavesRetiredRecordsOutOfTheCount(t *testing.T) {
	db := setupReconcileDB(t)
	seedNvd(t, db, "CVE-1", "CVE-2")
	if err := UpdateNvd(db, []knowledge.NVDItem{{NVDId: "CVE-2", VulnStatus: "Rejected", LastModified: "2026-01-01T00:00:00"}}); err != nil {
		t.Fatal(err)
	}

	if err := ReconcileNvd(db, []string{"CVE-1"}, runAt); err != nil {
		t.Fatal(err)
	}

	if got := retiredReason(t, db, "nvd", "nvd_id", "CVE-2"); got != knowledge.RetiredRejected {
		t.Errorf("reason = %q, want rejected kept", got)
	}
}
