package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	knowledge "github.com/CodeClarityCE/service-knowledge/src"
	"github.com/CodeClarityCE/service-knowledge/src/datedrestore"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/epss"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/osv"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/osv_asof"
	"github.com/CodeClarityCE/service-knowledge/src/validation"
)

func main() {
	var help = flag.Bool("help", false, "Show help")
	var know = flag.Bool("knowledge", false, "Use knowledge component")
	var daemon = flag.Bool("daemon", false, "Run as daemon with cron scheduler")
	var debug = flag.Bool("debug", false, "Enable debug logging for cronjobs")
	var action = ""
	var asof = ""
	var advisoryRepo = ""
	var checkoutDate = ""
	var epssDate = ""
	var sources = ""

	// Bind flags
	flag.StringVar(&action, "action", action, "Action to perform")
	flag.StringVar(&asof, "asof", asof, "As-of date (YYYY-MM-DD) for the update-asof and filter-asof actions")
	flag.StringVar(&advisoryRepo, "advisory-repo", advisoryRepo, "Path to a github/advisory-database checkout for the update-asof action")
	flag.StringVar(&checkoutDate, "checkout-date", checkoutDate, "RFC3339 date of the checked-out advisory commit, stamped as osv_last (defaults to --asof)")
	flag.StringVar(&epssDate, "epss-date", epssDate, "Optional EPSS snapshot date (YYYY-MM-DD) imported by the update-asof and filter-asof actions")

	flag.StringVar(&sources, "sources", sources, "Comma-separated source names for the reset-validation-floor action")

	// Parse flags
	flag.Parse()

	// Show help
	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if runsAsDaemon(*know, *daemon) {
		runDaemon(*debug)
		return
	}

	// CLI mode - for Makefile commands
	switch action {
	case "setup":
		log.Println("Running knowledge setup...")
		err := knowledge.Setup(true)
		if err != nil {
			log.Fatalf("Failed to setup knowledge: %v", err)
		}
		log.Println("Knowledge setup completed successfully")
	case "update":
		log.Println("Running knowledge update...")

		// Create knowledge service for database connections
		knowledgeService, err := CreateKnowledgeService()
		if err != nil {
			log.Fatalf("Failed to create knowledge service: %v", err)
		}
		defer knowledgeService.Close()

		err = knowledge.WithUpdateLock(context.Background(), knowledgeService.DB.Knowledge, func() error {
			return knowledge.UpdateAndValidate(knowledgeService.DB.Knowledge, knowledgeService.DB.Config, knowledgeService.DB.CodeClarity)
		})
		if err != nil {
			log.Fatalf("Failed to update knowledge: %v", err)
		}
		log.Println("Knowledge update completed successfully")
	case "update-osv":
		log.Println("Running OSV-only knowledge update...")

		knowledgeService, err := CreateKnowledgeService()
		if err != nil {
			log.Fatalf("Failed to create knowledge service: %v", err)
		}
		defer knowledgeService.Close()

		err = knowledge.WithUpdateLock(context.Background(), knowledgeService.DB.Knowledge, func() error {
			if err := datedrestore.RefuseMarked(knowledgeService.DB.Knowledge); err != nil {
				return err
			}
			return osv.Update(knowledgeService.DB.Knowledge, knowledgeService.DB.Config)
		})
		if err != nil {
			log.Fatalf("Failed to update OSV advisories: %v", err)
		}
		log.Println("OSV update completed successfully")
	case "validate":
		log.Println("Validating the knowledge database...")

		knowledgeService, err := CreateKnowledgeService()
		if err != nil {
			log.Fatalf("Failed to create knowledge service: %v", err)
		}
		defer knowledgeService.Close()

		err = knowledge.WithUpdateLock(context.Background(), knowledgeService.DB.Knowledge, func() error {
			return knowledge.Validate(knowledgeService.DB.Knowledge)
		})
		if err != nil {
			log.Fatalf("Knowledge validation failed: %v", err)
		}
		log.Println("Knowledge validation passed")
	case "reset-validation-floor":
		if sources == "" {
			log.Fatalf("The reset-validation-floor action requires --sources (comma-separated source names)")
		}

		knowledgeService, err := CreateKnowledgeService()
		if err != nil {
			log.Fatalf("Failed to create knowledge service: %v", err)
		}
		defer knowledgeService.Close()

		err = knowledge.WithUpdateLock(context.Background(), knowledgeService.DB.Knowledge, func() error {
			return validation.ResetRowFloors(knowledgeService.DB.Knowledge, strings.Split(sources, ",")...)
		})
		if err != nil {
			log.Fatalf("Failed to reset validation floors: %v", err)
		}
		log.Printf("Reset validation floors for %s", sources)
	case "update-asof":
		if asof == "" || advisoryRepo == "" {
			log.Fatalf("The update-asof action requires --asof and --advisory-repo")
		}
		asofTime, err := time.Parse("2006-01-02", asof)
		if err != nil {
			log.Fatalf("Invalid --asof date %q (expected YYYY-MM-DD): %v", asof, err)
		}
		checkoutTime := asofTime
		if checkoutDate != "" {
			checkoutTime, err = time.Parse(time.RFC3339, checkoutDate)
			if err != nil {
				log.Fatalf("Invalid --checkout-date %q (expected RFC3339): %v", checkoutDate, err)
			}
		}

		log.Printf("Running as-of knowledge update for %s...", asof)

		// Create knowledge service for database connections
		knowledgeService, err := CreateKnowledgeService()
		if err != nil {
			log.Fatalf("Failed to create knowledge service: %v", err)
		}
		defer knowledgeService.Close()

		err = knowledge.WithUpdateLock(context.Background(), knowledgeService.DB.Knowledge, func() error {
			if err := osv_asof.Update(knowledgeService.DB.Knowledge, knowledgeService.DB.Config, advisoryRepo, asofTime, checkoutTime); err != nil {
				return fmt.Errorf("import as-of OSV advisories: %w", err)
			}
			return importDatedEPSS(knowledgeService, epssDate)
		})
		if err != nil {
			log.Fatalf("Failed to run as-of knowledge update: %v", err)
		}
		log.Println("As-of knowledge update completed successfully")
	case "filter-asof":
		if asof == "" {
			log.Fatalf("The filter-asof action requires --asof")
		}
		asofTime, err := time.Parse("2006-01-02", asof)
		if err != nil {
			log.Fatalf("Invalid --asof date %q (expected YYYY-MM-DD): %v", asof, err)
		}

		log.Printf("Filtering OSV knowledge to advisories published on or before %s...", asof)

		knowledgeService, err := CreateKnowledgeService()
		if err != nil {
			log.Fatalf("Failed to create knowledge service: %v", err)
		}
		defer knowledgeService.Close()

		err = knowledge.WithUpdateLock(context.Background(), knowledgeService.DB.Knowledge, func() error {
			if err := osv_asof.Filter(knowledgeService.DB.Knowledge, knowledgeService.DB.Config, asofTime); err != nil {
				return fmt.Errorf("filter OSV advisories: %w", err)
			}
			return importDatedEPSS(knowledgeService, epssDate)
		})
		if err != nil {
			log.Fatalf("Failed to run as-of knowledge filter: %v", err)
		}
		log.Println("As-of knowledge filter completed successfully")
	default:
		flag.Usage()
		os.Exit(0)
	}
}

// importDatedEPSS imports the dated EPSS snapshot when one was requested.
func importDatedEPSS(service *KnowledgeService, epssDate string) error {
	if epssDate == "" {
		return nil
	}
	if err := epss.UpdateAsOf(service.DB.Knowledge, epssDate); err != nil {
		return fmt.Errorf("import dated EPSS scores: %w", err)
	}
	return nil
}
