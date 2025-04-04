// Package knowledge provides functions for setting up and updating the knowledge database.
package knowledge

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/mirrors/cwe"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/js"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/licenses"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/nvd"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/osv"
	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// Setup initializes the necessary databases and collections for the knowledge service.
// It takes a boolean parameter 'confirm' which indicates whether to confirm the creation of databases or not.
// It returns the initialized Knowledge and Results databases, along with any error that occurred during the setup process.
func Setup(confirm bool) error {
	host := os.Getenv("PG_DB_HOST")
	if host == "" {
		log.Printf("PG_DB_HOST is not set")
		return fmt.Errorf("PG_DB_HOST is not set")
	}
	port := os.Getenv("PG_DB_PORT")
	if port == "" {
		log.Printf("PG_DB_PORT is not set")
		return fmt.Errorf("PG_DB_PORT is not set")
	}
	user := os.Getenv("PG_DB_USER")
	if user == "" {
		log.Printf("PG_DB_USER is not set")
		return fmt.Errorf("PG_DB_USER is not set")
	}
	password := os.Getenv("PG_DB_PASSWORD")
	if password == "" {
		log.Printf("PG_DB_PASSWORD is not set")
		return fmt.Errorf("PG_DB_PASSWORD is not set")
	}

	dsn := "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn), pgdriver.WithTimeout(120*time.Second)))
	db := bun.NewDB(sqldb, pgdialect.New())
	defer db.Close()

	dsn_config := "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbhelper.Config.Database.Config + "?sslmode=disable"
	sqldb_config := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_config), pgdriver.WithTimeout(50*time.Second)))
	db_config := bun.NewDB(sqldb_config, pgdialect.New())
	defer db_config.Close()

	// Get or create Knowledge DB
	err := dbhelper.CreateDatabase(dbhelper.Config.Database.Knowledge, confirm)
	if err != nil {
		return err
	}
	// Get or create Results DB
	err = dbhelper.CreateDatabase(dbhelper.Config.Database.Results, confirm)
	if err != nil {
		return err
	}
	// Get or create Plugins DB
	err = dbhelper.CreateDatabase(dbhelper.Config.Database.Plugins, confirm)
	if err != nil {
		return err
	}
	// Get or create Config DB
	err = dbhelper.CreateDatabase(dbhelper.Config.Database.Config, confirm)
	if err != nil {
		return err
	}

	dbhelper.CreateTable(dbhelper.Config.Database.Plugins)

	return nil
}

// Update updates the knowledge database by performing various operations such as updating licenses, vulnerabilities, and importing packages.
// It returns an error if any of the operations fail.
func Update() error {
	host := os.Getenv("PG_DB_HOST")
	if host == "" {
		log.Printf("PG_DB_HOST is not set")
		return fmt.Errorf("PG_DB_HOST is not set")
	}
	port := os.Getenv("PG_DB_PORT")
	if port == "" {
		log.Printf("PG_DB_PORT is not set")
		return fmt.Errorf("PG_DB_PORT is not set")
	}
	user := os.Getenv("PG_DB_USER")
	if user == "" {
		log.Printf("PG_DB_USER is not set")
		return fmt.Errorf("PG_DB_USER is not set")
	}
	password := os.Getenv("PG_DB_PASSWORD")
	if password == "" {
		log.Printf("PG_DB_PASSWORD is not set")
		return fmt.Errorf("PG_DB_PASSWORD is not set")
	}

	dsn := "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn), pgdriver.WithTimeout(120*time.Second)))
	db := bun.NewDB(sqldb, pgdialect.New())
	defer db.Close()

	dsn_config := "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbhelper.Config.Database.Config + "?sslmode=disable"
	sqldb_config := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_config), pgdriver.WithTimeout(50*time.Second)))
	db_config := bun.NewDB(sqldb_config, pgdialect.New())
	defer db_config.Close()

	// Update licenses
	err := licenses.Update(db)
	if err != nil {
		log.Printf("%v", err)
		// return err
	}

	// Update vulnerabilities
	err = osv.Update(db)
	if err != nil {
		log.Printf("%v", err)
		// return err
	}

	err = cwe.Update(db)
	if err != nil {
		log.Printf("%v", err)
		// return err
	}

	err = nvd.Update(db, db_config)
	if err != nil {
		log.Printf("%v", err)
		// return err
	}

	// // Import packages
	// err = js.ImportTop10000(db, db_config)
	// if err != nil {
	// 	log.Printf("%v", err)
	// 	// return err
	// }

	// Import packages
	err = js.Follow(db, db_config)
	if err != nil {
		log.Printf("%v", err)
		// return err
	}

	return nil
}
