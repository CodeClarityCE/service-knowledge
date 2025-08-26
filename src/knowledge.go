// Package knowledge provides functions for setting up and updating the knowledge database.
package knowledge

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/mirrors/cwe"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/epss"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/js"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/licenses"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/nvd"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/osv"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/php_security"
	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// Setup initializes the necessary databases and collections for the knowledge service.
// It takes a boolean parameter 'confirm' which indicates whether to confirm the creation of databases or not.
// It returns the initialized Knowledge and Results databases, along with any error that occurred during the setup process.
func Setup(confirm bool) error {
	return setupDatabases(confirm, false)
}

// SetupForDaemon safely verifies database connections without creating or modifying any databases.
// This is used when the knowledge service runs as a daemon alongside other services.
// It assumes all required databases already exist and simply verifies connectivity.
func SetupForDaemon(knowledgeDB *bun.DB) error {
	// Test connection to knowledge database
	err := knowledgeDB.Ping()
	if err != nil {
		log.Printf("Warning: Cannot connect to knowledge database '%s': %v", dbhelper.Config.Database.Knowledge, err)
		log.Printf("The knowledge database may not exist yet. Run 'make knowledge-setup' first.")
		return fmt.Errorf("cannot connect to knowledge database: %v", err)
	}

	log.Printf("Successfully connected to knowledge database '%s'", dbhelper.Config.Database.Knowledge)
	return nil
}

// setupDatabases is the internal function that handles database setup with different modes
func setupDatabases(confirm bool, daemonMode bool) error {
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

	// Get or create Knowledge DB (always needed)
	err := dbhelper.CreateDatabase(dbhelper.Config.Database.Knowledge, confirm)
	if err != nil {
		return err
	}

	if !daemonMode {
		// Only create test and shared databases in CLI mode, not in daemon mode
		err = dbhelper.CreateDatabase(dbhelper.Config.Database.Knowledge+"_test", confirm)
		if err != nil {
			return err
		}
		// Get or create Results DB (this is the "codeclarity" database that causes conflicts)
		err = dbhelper.CreateDatabase(dbhelper.Config.Database.Results, confirm)
		if err != nil {
			return err
		}
		err = dbhelper.CreateDatabase(dbhelper.Config.Database.Results+"_test", confirm)
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
		err = dbhelper.CreateDatabase(dbhelper.Config.Database.Config+"_test", confirm)
		if err != nil {
			return err
		}

		dbhelper.CreateTable(dbhelper.Config.Database.Plugins)
	} else {
		log.Println("Daemon mode: Skipping creation of shared databases (codeclarity, plugins, config) to avoid conflicts")
	}

	return nil
}

// Update updates the knowledge database by performing various operations such as updating licenses, vulnerabilities, and importing packages.
// It returns an error if any of the operations fail.
// UpdateWithSetup updates the knowledge database by setting up database connections internally
func UpdateWithSetup() error {
	return updateDatabases()
}

func Update(knowledgeDB *bun.DB, configDB *bun.DB) error {
	// Update licenses
	err := licenses.Update(knowledgeDB)
	if err != nil {
		log.Printf("%v", err)
		// return err
	}

	// Update EPSS
	err = epss.Update(knowledgeDB)
	if err != nil {
		log.Printf("%v", err)
		// return err
	}

	// Update vulnerabilities
	err = osv.Update(knowledgeDB)
	if err != nil {
		log.Printf("%v", err)
		// return err
	}

	err = cwe.Update(knowledgeDB)
	if err != nil {
		log.Printf("%v", err)
		// return err
	}

	err = nvd.Update(knowledgeDB, configDB)
	if err != nil {
		log.Printf("%v", err)
		// return err
	}

	// Update PHP security advisories (FriendsOfPHP Security Advisories)
	err = php_security.Update(knowledgeDB)
	if err != nil {
		log.Printf("%v", err)
		// return err
	}

	// // Import packages
	// err = js.ImportTop10000(knowledgeDB, configDB)
	// if err != nil {
	// 	log.Printf("%v", err)
	// 	// return err
	// }

	// Import packages
	err = js.Follow(knowledgeDB, configDB)
	if err != nil {
		log.Printf("%v", err)
		// return err
	}

	return nil
}

// updateDatabases handles database setup and calls Update with proper connections
func updateDatabases() error {
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

	// Connect to knowledge database
	dsn := "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn), pgdriver.WithTimeout(120*time.Second)))
	knowledgeDB := bun.NewDB(sqldb, pgdialect.New())
	defer knowledgeDB.Close()

	// Connect to config database
	dsn_config := "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbhelper.Config.Database.Plugins + "?sslmode=disable"
	sqldb_config := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_config), pgdriver.WithTimeout(50*time.Second)))
	configDB := bun.NewDB(sqldb_config, pgdialect.New())
	defer configDB.Close()

	// Call the Update function with database connections
	return Update(knowledgeDB, configDB)
}
