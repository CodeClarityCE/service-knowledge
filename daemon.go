package main

import (
	"context"
	"errors"
	"time"

	knowledge "github.com/CodeClarityCE/service-knowledge/src"
	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
	"github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
)

const (
	updateSchedule      = "0 0 */6 * * *" // 00:00, 06:00, 12:00 and 18:00
	debugUpdateSchedule = "0 * * * * *"   // every minute
)

var logger = sourcesync.NewLogger()

// runsAsDaemon reports whether to run the cron scheduler rather than a one-off CLI action.
func runsAsDaemon(knowledgeCLI bool, daemon bool) bool {
	return daemon || !knowledgeCLI
}

// newUpdateScheduler schedules runUpdate. A run that fails or panics does not stop later runs.
func newUpdateScheduler(debug bool, runUpdate func() error) (*cron.Cron, error) {
	schedule := updateSchedule
	if debug {
		logger.Info("Debug mode: running knowledge updates every minute")
		schedule = debugUpdateSchedule
	}

	scheduler := cron.New(cron.WithSeconds(), cron.WithChain(cron.Recover(cron.PrintfLogger(logger))))
	_, err := scheduler.AddFunc(schedule, func() { logUpdateRun(runUpdate) })
	if err != nil {
		return nil, err
	}
	return scheduler, nil
}

// logUpdateRun runs one scheduled update and logs how it ended.
func logUpdateRun(runUpdate func() error) {
	logger.Info("Starting scheduled knowledge update")
	start := time.Now()
	err := runUpdate()
	fields := logrus.Fields{"duration_seconds": time.Since(start).Seconds()}
	if err != nil {
		fields["error"] = err.Error()
	}

	switch {
	case errors.Is(err, knowledge.ErrUpdateInProgress):
		logger.WithFields(fields).Warn("Skipped scheduled knowledge update")
	case err != nil:
		logger.WithFields(fields).Error("Scheduled knowledge update failed")
	default:
		logger.WithFields(fields).Info("Scheduled knowledge update completed")
	}
}

// runDaemon runs the scheduled knowledge update until the process stops.
func runDaemon(debug bool) {
	logger.Info("Starting knowledge service in daemon mode")

	knowledgeService, err := CreateKnowledgeService()
	if err != nil {
		logger.WithFields(logrus.Fields{"error": err.Error()}).Fatal("Failed to create knowledge service")
	}
	defer knowledgeService.Close()

	// Only checks connectivity, so it is safe alongside other services.
	err = knowledge.SetupForDaemon(knowledgeService.DB.Knowledge)
	if err != nil {
		logger.WithFields(logrus.Fields{"error": err.Error()}).Fatal("Failed to set up knowledge service")
	}

	db := knowledgeService.DB
	scheduler, err := newUpdateScheduler(debug, func() error {
		return knowledge.WithUpdateLock(context.Background(), db.Knowledge, func() error {
			return knowledge.Update(db.Knowledge, db.Config, db.CodeClarity)
		})
	})
	if err != nil {
		logger.WithFields(logrus.Fields{"error": err.Error()}).Fatal("Failed to add knowledge update cron job")
	}
	scheduler.Start()

	logger.Info("Knowledge service started")
	for _, entry := range scheduler.Entries() {
		logger.WithFields(logrus.Fields{"next_run": entry.Next}).Info("Next scheduled knowledge update")
	}

	// Keep the service running
	select {}
}
