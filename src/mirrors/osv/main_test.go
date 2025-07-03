package osv

import (
	"database/sql"
	"os"
	"testing"
	"time"

	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

func TestUpdate(t *testing.T) {
	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")
	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:5432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	err := Update(db_knowledge)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
}
