package main

import (
	"errors"
	"testing"
	"time"

	knowledge "github.com/CodeClarityCE/service-knowledge/src"
	"github.com/robfig/cron/v3"
)

func TestRunsAsDaemon(t *testing.T) {
	cases := []struct {
		name     string
		know     bool
		daemon   bool
		expected bool
	}{
		{"daemon flag wins over the knowledge flag", true, true, true},
		{"daemon flag alone", false, true, true},
		{"no flags keeps the daemon default", false, false, true},
		{"knowledge flag alone runs the CLI", true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runsAsDaemon(tc.know, tc.daemon); got != tc.expected {
				t.Fatalf("runsAsDaemon(%v, %v) = %v, want %v", tc.know, tc.daemon, got, tc.expected)
			}
		})
	}
}

func runScheduledJob(t *testing.T, scheduler *cron.Cron) {
	t.Helper()
	entries := scheduler.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected one scheduled job, got %d", len(entries))
	}
	entries[0].WrappedJob.Run()
}

func TestSchedulerRunsEverySixHours(t *testing.T) {
	scheduler, err := newUpdateScheduler(false, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 1, 1, 0, 30, 0, 0, time.Local)
	expected := time.Date(2026, 1, 1, 6, 0, 0, 0, time.Local)
	if got := scheduler.Entries()[0].Schedule.Next(from); !got.Equal(expected) {
		t.Fatalf("next run = %v, want %v", got, expected)
	}
}

func TestSchedulerSurvivesFailedRuns(t *testing.T) {
	failures := []func() error{
		func() error { return errors.New("source failed") },
		func() error { return errors.Join(errors.New("nvd failed"), errors.New("gcve failed")) },
		func() error { return knowledge.ErrUpdateInProgress },
		func() error { panic("update crashed") },
	}
	calls := 0
	scheduler, err := newUpdateScheduler(false, func() error {
		failure := failures[calls]
		calls++
		return failure()
	})
	if err != nil {
		t.Fatal(err)
	}
	for range failures {
		runScheduledJob(t, scheduler)
	}
	if calls != len(failures) {
		t.Fatalf("expected %d runs, got %d", len(failures), calls)
	}
}
