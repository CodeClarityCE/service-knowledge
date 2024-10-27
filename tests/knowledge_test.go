package knowledge

import (
	"database/sql"
	"log"
	"os"
	"testing"

	"github.com/CodeClarityCE/service-knowledge/src/mirrors/js"
	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

func TestUpdate(t *testing.T) {
	host := os.Getenv("PG_DB_HOST")
	if host == "" {
		log.Printf("PG_DB_HOST is not set")
		return
	}
	port := os.Getenv("PG_DB_PORT")
	if port == "" {
		log.Printf("PG_DB_PORT is not set")
		return
	}
	user := os.Getenv("PG_DB_USER")
	if user == "" {
		log.Printf("PG_DB_USER is not set")
		return
	}
	password := os.Getenv("PG_DB_PASSWORD")
	if password == "" {
		log.Printf("PG_DB_PASSWORD is not set")
		return
	}

	os.Setenv("NPM_URL", "https://replicate.npmjs.com/")

	dsn := "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	db := bun.NewDB(sqldb, pgdialect.New())
	defer db.Close()

	// err := js.UpdatePackage(db, "express")
	// if err != nil {
	// 	t.Error(err)
	// }

	// err = js.UpdatePackage(db, "react")
	// if err != nil {
	// 	t.Error(err)
	// }

	err := js.UpdatePackage(db, "@types/body-parser")
	if err != nil {
		t.Error(err)
	}
}
