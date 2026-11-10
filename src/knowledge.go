// Package knowledge provides functions for setting up and updating the knowledge database.
package knowledge

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/datedrestore"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/cwe"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/epss"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/gcve"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/js"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/licenses"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/nvd"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/osv"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/php_security"
	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	"github.com/CodeClarityCE/service-knowledge/src/validation"
	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	knowledgedb "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/sirupsen/logrus"
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

	tlsOpt := dbhelper.BuildPgdriverTLSOption()

	dsn := dbhelper.BuildDSN(user, password, host, port, dbhelper.Config.Database.Knowledge)
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn), pgdriver.WithTimeout(120*time.Second), tlsOpt))
	db := bun.NewDB(sqldb, pgdialect.New())
	defer db.Close()

	dsn_config := dbhelper.BuildDSN(user, password, host, port, dbhelper.Config.Database.Config)
	sqldb_config := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_config), pgdriver.WithTimeout(50*time.Second), tlsOpt))
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

// Update runs every knowledge source, then reports all that failed as a joined error.
func Update(knowledgeDB *bun.DB, configDB *bun.DB, codeClarityDB *bun.DB) error {
	// Package-update notifications need the codeclarity database; set it once
	// here rather than opening an ad-hoc connection per package (see
	// pgsql.SetCodeClarityDB's doc comment).
	pgsql.SetCodeClarityDB(codeClarityDB)

	return runSteps(knowledgeDB, updateSteps(knowledgeDB, configDB))
}

// updateStep is one named step of an update.
type updateStep struct {
	name string
	run  func() error
}

// updateSteps lists every update step in order. npm follows packages and is not a knowledge source.
func updateSteps(knowledgeDB *bun.DB, configDB *bun.DB) []updateStep {
	return []updateStep{
		{knowledgedb.SourceLicenses, func() error { return licenses.Update(knowledgeDB) }},
		{knowledgedb.SourceEPSS, func() error { return epss.Update(knowledgeDB) }},
		{knowledgedb.SourceOSV, func() error { return osv.Update(knowledgeDB, configDB) }},
		{knowledgedb.SourceCWE, func() error { return cwe.Update(knowledgeDB) }},
		{knowledgedb.SourceNVD, func() error { return nvd.Update(knowledgeDB, configDB) }},
		{knowledgedb.SourceGCVE, func() error { return gcve.Update(knowledgeDB, configDB) }},
		{knowledgedb.SourceFriendsOfPHP, func() error { return php_security.Update(knowledgeDB) }},
		{"npm", func() error { return js.Follow(knowledgeDB, configDB) }},
	}
}

// updateSources runs only the named update steps, in update order.
func updateSources(knowledgeDB *bun.DB, configDB *bun.DB, names ...string) error {
	steps := slices.DeleteFunc(updateSteps(knowledgeDB, configDB), func(step updateStep) bool {
		return !slices.Contains(names, step.name)
	})
	return runSteps(knowledgeDB, steps)
}

// runSteps runs every step unless the database is a dated restore.
func runSteps(knowledgeDB *bun.DB, steps []updateStep) error {
	if err := datedrestore.RefuseMarked(knowledgeDB); err != nil {
		return err
	}
	runs := make([]func() error, len(steps))
	for i, step := range steps {
		runs[i] = step.run
	}
	return runAll(runs)
}

// UpdateAndValidate updates every source, then validates the result, also after a failed update.
func UpdateAndValidate(knowledgeDB *bun.DB, configDB *bun.DB, codeClarityDB *bun.DB) error {
	return updateThenValidate(
		func() error { return Update(knowledgeDB, configDB, codeClarityDB) },
		func() error { return Validate(knowledgeDB) },
	)
}

// updateThenValidate joins the update and validation failures; a refused update is not validated.
func updateThenValidate(update, validate func() error) error {
	updateErr := update()
	if errors.Is(updateErr, datedrestore.ErrDatedRestore) {
		return updateErr
	}
	return errors.Join(updateErr, validate())
}

// ErrValidationFailed means at least one knowledge source failed validation.
var ErrValidationFailed = errors.New("knowledge validation failed")

// Validate checks every source and logs and returns any failure.
func Validate(knowledgeDB *bun.DB) error {
	if err := datedrestore.RefuseMarked(knowledgeDB); err != nil {
		return err
	}
	report, err := validation.Run(knowledgeDB, time.Now())
	for _, finding := range report.Findings {
		logger.WithFields(logrus.Fields{"source": finding.Source, "check": finding.Check, "error": finding.Message}).Error("Knowledge source failed validation")
	}
	if err != nil {
		return fmt.Errorf("knowledge validation could not finish: %w", err)
	}
	if report.Failed() {
		return fmt.Errorf("%w: %d checks failed", ErrValidationFailed, len(report.Findings))
	}
	logger.Info("Knowledge validation passed")
	return nil
}

// runAll runs every step, regardless of earlier failures, and joins their errors.
func runAll(steps []func() error) error {
	var failures []error
	for _, step := range steps {
		if err := step(); err != nil {
			logger.WithFields(logrus.Fields{"error": err.Error()}).Error("Knowledge update step failed")
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
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

	tlsOpt := dbhelper.BuildPgdriverTLSOption()

	// Connect to knowledge database
	dsn := dbhelper.BuildDSN(user, password, host, port, dbhelper.Config.Database.Knowledge)
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn), pgdriver.WithTimeout(120*time.Second), tlsOpt))
	knowledgeDB := bun.NewDB(sqldb, pgdialect.New())
	defer knowledgeDB.Close()

	// Connect to config database
	dsn_config := dbhelper.BuildDSN(user, password, host, port, dbhelper.Config.Database.Plugins)
	sqldb_config := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_config), pgdriver.WithTimeout(50*time.Second), tlsOpt))
	configDB := bun.NewDB(sqldb_config, pgdialect.New())
	defer configDB.Close()

	// Connect to codeclarity database
	dsn_codeclarity := dbhelper.BuildDSN(user, password, host, port, dbhelper.Config.Database.Results)
	sqldb_codeclarity := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_codeclarity), pgdriver.WithTimeout(50*time.Second), tlsOpt))
	codeClarityDB := bun.NewDB(sqldb_codeclarity, pgdialect.New())
	defer codeClarityDB.Close()

	// Call the Update function with database connections
	return Update(knowledgeDB, configDB, codeClarityDB)
}
