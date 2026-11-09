package main

import (
	"context"
	"errors"
	"log"
	"time"

	knowledge "github.com/CodeClarityCE/service-knowledge/src"
	"github.com/robfig/cron/v3"
)

const (
	updateSchedule      = "0 0 */6 * * *" // 00:00, 06:00, 12:00 and 18:00
	debugUpdateSchedule = "0 * * * * *"   // every minute
)

// runsAsDaemon reports whether to run the cron scheduler rather than a one-off CLI action.
func runsAsDaemon(know bool, daemon bool) bool {
	return daemon || !know
}

// newUpdateScheduler schedules runUpdate. A run that fails or panics does not stop later runs.
func newUpdateScheduler(debug bool, runUpdate func() error) (*cron.Cron, error) {
	schedule := updateSchedule
	if debug {
		log.Printf("Debug mode: Running updates every minute for testing")
		schedule = debugUpdateSchedule
	}

	logger := cron.PrintfLogger(log.Default())
	scheduler := cron.New(cron.WithSeconds(), cron.WithChain(cron.Recover(logger)))
	_, err := scheduler.AddFunc(schedule, func() { logUpdateRun(runUpdate) })
	if err != nil {
		return nil, err
	}
	return scheduler, nil
}

// logUpdateRun runs one scheduled update and logs how it ended.
func logUpdateRun(runUpdate func() error) {
	log.Printf("Starting scheduled knowledge update...")
	start := time.Now()
	err := runUpdate()
	duration := time.Since(start)

	switch {
	case errors.Is(err, knowledge.ErrUpdateInProgress):
		log.Printf("Skipped scheduled update: %v", err)
	case err != nil:
		log.Printf("ERROR: Scheduled update failed after %v: %v", duration, err)
	default:
		log.Printf("SUCCESS: Scheduled update completed in %v", duration)
	}
}

// runDaemon runs the scheduled knowledge update until the process stops.
func runDaemon(debug bool) {
	log.Println("Starting knowledge service in daemon mode with cron scheduler...")

	knowledgeService, err := CreateKnowledgeService()
	if err != nil {
		log.Fatalf("Failed to create knowledge service: %v", err)
	}
	defer knowledgeService.Close()

	// Only checks connectivity, so it is safe alongside other services.
	err = knowledge.SetupForDaemon(knowledgeService.DB.Knowledge)
	if err != nil {
		log.Fatalf("Failed to setup knowledge service: %v", err)
	}

	db := knowledgeService.DB
	scheduler, err := newUpdateScheduler(debug, func() error {
		return knowledge.WithUpdateLock(context.Background(), db.Knowledge, func() error {
			return knowledge.Update(db.Knowledge, db.Config, db.CodeClarity)
		})
	})
	if err != nil {
		log.Fatalf("Failed to add cron job: %v", err)
	}
	scheduler.Start()

	log.Println("Knowledge service started successfully")
	for _, entry := range scheduler.Entries() {
		log.Printf("Next scheduled run: %v", entry.Next)
	}

	// Keep the service running
	select {}
}
