package knowledge

import (
	"context"
	"testing"

	"github.com/CodeClarityCE/service-knowledge/src/mirrors/js"
	"github.com/CodeClarityCE/utility-boilerplates/testdeps"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// createPackageTables builds the package and version tables from their models, with the keys the upserts target.
func createPackageTables(t *testing.T, db *bun.DB) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`); err != nil {
		t.Fatalf("create extension: %v", err)
	}
	for _, model := range []any{(*knowledge.Package)(nil), (*knowledge.Version)(nil)} {
		if _, err := db.NewCreateTable().Model(model).Exec(ctx); err != nil {
			t.Fatalf("create table: %v", err)
		}
	}
	for _, index := range []string{
		`CREATE UNIQUE INDEX ON package (name, language)`,
		`CREATE UNIQUE INDEX ON version (package_id, version)`,
	} {
		if _, err := db.ExecContext(ctx, index); err != nil {
			t.Fatalf("create index: %v", err)
		}
	}
}

// TestUpdate fetches a real package from the npm registry and stores it with its versions.
func TestUpdate(t *testing.T) {
	t.Setenv("NPM_URL", "https://registry.npmjs.org/")
	db := testdeps.Postgres(t)
	createPackageTables(t, db)

	if err := js.UpdatePackage(db, "@types/body-parser"); err != nil {
		t.Fatalf("update package: %v", err)
	}

	var pack knowledge.Package
	err := db.NewSelect().Model(&pack).Relation("Versions").
		Where("p.name = ? AND p.language = ?", "@types/body-parser", "javascript").
		Scan(context.Background())
	if err != nil {
		t.Fatalf("read package: %v", err)
	}
	if pack.LatestVersion == "" || len(pack.Versions) == 0 {
		t.Fatalf("package stored without versions: latest %q, %d versions", pack.LatestVersion, len(pack.Versions))
	}
}
