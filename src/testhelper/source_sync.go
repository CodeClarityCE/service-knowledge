package testhelper

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// sourceSyncDDL matches the CreateKnowledgeSourceSync API migration.
const sourceSyncDDL = `
CREATE TABLE knowledge_source_sync (
	source character varying NOT NULL PRIMARY KEY,
	watermark timestamptz,
	last_run_started_at timestamptz,
	last_run_finished_at timestamptz,
	last_outcome character varying CHECK (last_outcome IN ('success', 'failure')),
	last_error text,
	row_count bigint NOT NULL DEFAULT 0,
	bulk_completed_at timestamptz
)`

// SetupSyncTestDB opens a fresh schema in the throwaway database named by
// KNOWLEDGE_SYNC_TEST_DSN, holding the source sync and config tables.
func SetupSyncTestDB(t *testing.T) *bun.DB {
	t.Helper()
	dsn := os.Getenv("KNOWLEDGE_SYNC_TEST_DSN")
	if dsn == "" {
		t.Skip("KNOWLEDGE_SYNC_TEST_DSN is not set")
	}

	schema := "sync_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	admin := openDB(dsn, nil)
	defer admin.Close()
	ctx := context.Background()
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}

	db := openDB(dsn, map[string]any{"search_path": schema})
	t.Cleanup(func() {
		db.Close()
		cleaner := openDB(dsn, nil)
		defer cleaner.Close()
		_, _ = cleaner.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE")
	})

	for _, ddl := range []string{
		// Models default their ids to this function.
		`CREATE FUNCTION uuid_generate_v4() RETURNS uuid AS 'SELECT gen_random_uuid()' LANGUAGE SQL`,
		sourceSyncDDL,
		`CREATE TABLE config (
			id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
			nvd_last timestamptz, npm_last text, gcve_last timestamptz, osv_last timestamptz
		)`,
		`INSERT INTO config (npm_last) VALUES ('0')`,
	} {
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			t.Fatalf("create test tables: %v", err)
		}
	}
	return db
}

// CreateTables creates one table per bun model in the test schema.
func CreateTables(t *testing.T, db *bun.DB, models ...any) {
	t.Helper()
	for _, model := range models {
		if _, err := db.NewCreateTable().Model(model).Exec(context.Background()); err != nil {
			t.Fatalf("create table for %T: %v", model, err)
		}
	}
}

// CreatePackageLinkIndexes adds the unique indexes that package link upserts target.
func CreatePackageLinkIndexes(t *testing.T, db *bun.DB) {
	t.Helper()
	for _, column := range []string{"osv_id", "nvd_id", "friendsofphp_id", "gcve_id"} {
		ddl := fmt.Sprintf(
			"CREATE UNIQUE INDEX ON package_vulnerability (package_name, package_ecosystem, %s) WHERE %s IS NOT NULL",
			column, column,
		)
		if _, err := db.ExecContext(context.Background(), ddl); err != nil {
			t.Fatalf("create package link index: %v", err)
		}
	}
}

func openDB(dsn string, params map[string]any) *bun.DB {
	options := []pgdriver.Option{pgdriver.WithDSN(dsn)}
	if params != nil {
		options = append(options, pgdriver.WithConnParams(params))
	}
	return bun.NewDB(sql.OpenDB(pgdriver.NewConnector(options...)), pgdialect.New())
}

// SeedWatermark stores a known starting watermark for source.
func SeedWatermark(t *testing.T, db *bun.DB, source string, watermark time.Time) {
	t.Helper()
	_, err := db.ExecContext(context.Background(),
		"INSERT INTO knowledge_source_sync (source, watermark) VALUES (?, ?)", source, watermark)
	if err != nil {
		t.Fatalf("seed watermark: %v", err)
	}
}

// AssertFailed checks that source's last run is recorded as a failure.
func AssertFailed(t *testing.T, db *bun.DB, source string) {
	t.Helper()
	row := readSync(t, db, source)
	if row.LastOutcome == nil || *row.LastOutcome != knowledge.SourceSyncFailure {
		t.Errorf("outcome = %v, want failure", row.LastOutcome)
	}
	if row.LastError == nil || *row.LastError == "" {
		t.Error("last_error should describe the failure")
	}
}

// AssertFailedWithWatermark checks that source failed and its watermark is still want.
func AssertFailedWithWatermark(t *testing.T, db *bun.DB, source string, want time.Time) {
	t.Helper()
	AssertFailed(t, db, source)
	row := readSync(t, db, source)
	if row.Watermark == nil || !row.Watermark.Equal(want) {
		t.Errorf("watermark = %v, want unchanged %v", row.Watermark, want)
	}
}

// AssertSucceededAfter checks that source succeeded and its watermark moved past previous.
func AssertSucceededAfter(t *testing.T, db *bun.DB, source string, previous time.Time) {
	t.Helper()
	row := readSync(t, db, source)
	if row.LastOutcome == nil || *row.LastOutcome != knowledge.SourceSyncSuccess {
		t.Errorf("outcome = %v, want success (last_error %v)", row.LastOutcome, row.LastError)
	}
	if row.Watermark == nil || !row.Watermark.After(previous) {
		t.Errorf("watermark = %v, want after %v", row.Watermark, previous)
	}
}

// DropTable removes a table so that writes to it fail.
func DropTable(t *testing.T, db *bun.DB, table string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), "DROP TABLE "+table+" CASCADE"); err != nil {
		t.Fatalf("drop %s: %v", table, err)
	}
}

// ConfigTime reads one timestamp column of the config row.
func ConfigTime(t *testing.T, db *bun.DB, column string) time.Time {
	t.Helper()
	var value time.Time
	if err := db.QueryRowContext(context.Background(), "SELECT "+column+" FROM config").Scan(&value); err != nil {
		t.Fatalf("read config.%s: %v", column, err)
	}
	return value
}

// SetConfigTime writes one timestamp column of the config row, as another writer would.
func SetConfigTime(t *testing.T, db *bun.DB, column string, value time.Time) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), "UPDATE config SET "+column+" = ?", value); err != nil {
		t.Errorf("write config.%s: %v", column, err)
	}
}

func readSync(t *testing.T, db *bun.DB, source string) knowledge.SourceSync {
	t.Helper()
	row := knowledge.SourceSync{Source: source}
	if err := db.NewSelect().Model(&row).WherePK().Scan(context.Background()); err != nil {
		t.Fatalf("read sync row: %v", err)
	}
	return row
}

// ConfigTimeIsNull reports whether a timestamp column of the config row is unset.
func ConfigTimeIsNull(t *testing.T, db *bun.DB, column string) bool {
	t.Helper()
	var isNull bool
	if err := db.QueryRowContext(context.Background(), "SELECT "+column+" IS NULL FROM config").Scan(&isNull); err != nil {
		t.Fatalf("read config.%s: %v", column, err)
	}
	return isNull
}
