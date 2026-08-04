package main

import (
	"flag"
	"log"
	"os"
	"time"

	knowledge "github.com/CodeClarityCE/service-knowledge/src"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/epss"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/osv_asof"
	"github.com/robfig/cron/v3"
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

	// Bind flags
	flag.StringVar(&action, "action", action, "Action to perform")
	flag.StringVar(&asof, "asof", asof, "As-of date (YYYY-MM-DD) for the update-asof action")
	flag.StringVar(&advisoryRepo, "advisory-repo", advisoryRepo, "Path to a github/advisory-database checkout for the update-asof action")
	flag.StringVar(&checkoutDate, "checkout-date", checkoutDate, "RFC3339 date of the checked-out advisory commit, stamped as osv_last (defaults to --asof)")
	flag.StringVar(&epssDate, "epss-date", epssDate, "Optional EPSS snapshot date (YYYY-MM-DD) imported by the update-asof action")

	// Parse flags
	flag.Parse()

	// Show help
	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if *know {
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

			err = knowledge.Update(knowledgeService.DB.Knowledge, knowledgeService.DB.Config)
			if err != nil {
				log.Fatalf("Failed to update knowledge: %v", err)
			}
			log.Println("Knowledge update completed successfully")
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

			err = osv_asof.Update(knowledgeService.DB.Knowledge, knowledgeService.DB.Config, advisoryRepo, asofTime, checkoutTime)
			if err != nil {
				log.Fatalf("Failed to import as-of OSV advisories: %v", err)
			}
			if epssDate != "" {
				err = epss.UpdateAsOf(knowledgeService.DB.Knowledge, epssDate)
				if err != nil {
					log.Fatalf("Failed to import dated EPSS scores: %v", err)
				}
			}
			log.Println("As-of knowledge update completed successfully")
		default:
			flag.Usage()
			os.Exit(0)
		}
	} else if *daemon {
		// Daemon mode - for Docker containers with cron scheduler
		log.Println("Starting knowledge service in daemon mode with cron scheduler...")

		// Create knowledge service for database connections
		knowledgeService, err := CreateKnowledgeService()
		if err != nil {
			log.Fatalf("Failed to create knowledge service: %v", err)
		}
		defer knowledgeService.Close()

		// Initial setup (daemon-safe - only touches knowledge database)
		err = knowledge.SetupForDaemon(knowledgeService.DB.Knowledge)
		if err != nil {
			log.Fatalf("Failed to setup knowledge service: %v", err)
		}

		// Create cron scheduler with seconds precision for better debugging
		c := cron.New(cron.WithSeconds())

		// Add cron job to run update every 6 hours (4 times a day)
		cronExpr := "0 0 */6 * * *" // At minute 0 of hour 0, 6, 12, and 18
		if *debug {
			log.Printf("Debug mode: Running updates every minute for testing")
			cronExpr = "0 * * * * *" // Every minute for debugging
		}

		_, err = c.AddFunc(cronExpr, func() {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			log.Printf("[%s] Starting scheduled knowledge update...", timestamp)

			start := time.Now()
			err := knowledge.Update(knowledgeService.DB.Knowledge, knowledgeService.DB.Config)
			duration := time.Since(start)

			if err != nil {
				log.Printf("[%s] ERROR: Scheduled update failed after %v: %v", timestamp, duration, err)
			} else {
				log.Printf("[%s] SUCCESS: Scheduled update completed in %v", timestamp, duration)
			}
		})
		if err != nil {
			log.Fatalf("Failed to add cron job: %v", err)
		}

		// Start the cron scheduler
		c.Start()

		if *debug {
			log.Println("Knowledge service started in DEBUG mode - running updates every minute")
		} else {
			log.Println("Knowledge service started successfully - running updates every 6 hours (00:00, 06:00, 12:00, 18:00)")
		}

		// Log next scheduled runs for debugging
		entries := c.Entries()
		if len(entries) > 0 {
			log.Printf("Next scheduled run: %v", entries[0].Next)
		}

		// Keep the service running
		select {}
	} else {
		// Default mode - backward compatibility (run as daemon)
		log.Println("Starting knowledge service with cron scheduler (default mode)...")

		// Create knowledge service for database connections
		knowledgeService, err := CreateKnowledgeService()
		if err != nil {
			log.Fatalf("Failed to create knowledge service: %v", err)
		}
		defer knowledgeService.Close()

		// Initial setup (daemon-safe - only touches knowledge database)
		err = knowledge.SetupForDaemon(knowledgeService.DB.Knowledge)
		if err != nil {
			log.Fatalf("Failed to setup knowledge service: %v", err)
		}

		// Create cron scheduler
		c := cron.New()

		// Add cron job to run update every 6 hours (4 times a day)
		_, err = c.AddFunc("0 */6 * * *", func() {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			log.Printf("[%s] Running scheduled knowledge update...", timestamp)

			start := time.Now()
			err := knowledge.Update(knowledgeService.DB.Knowledge, knowledgeService.DB.Config)
			duration := time.Since(start)

			if err != nil {
				log.Printf("[%s] Error during scheduled update (took %v): %v", timestamp, duration, err)
			} else {
				log.Printf("[%s] Scheduled knowledge update completed successfully in %v", timestamp, duration)
			}
		})
		if err != nil {
			log.Fatalf("Failed to add cron job: %v", err)
		}

		// Start the cron scheduler
		c.Start()
		log.Println("Knowledge service started successfully - running updates every 6 hours")

		// Keep the service running
		select {}
	}
}
