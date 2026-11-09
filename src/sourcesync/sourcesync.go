// Package sourcesync records the sync state of each knowledge source.
package sourcesync

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/sirupsen/logrus"
	"github.com/uptrace/bun"
)

// maxStoredErrorLength bounds last_error, since a run can fail on many pages.
const maxStoredErrorLength = 4000

var defaultLogOutput = os.Stderr

var logger = &logrus.Logger{
	Out:       defaultLogOutput,
	Formatter: &logrus.JSONFormatter{},
	Hooks:     make(logrus.LevelHooks),
	Level:     logrus.InfoLevel,
}

// Sync does one source's work. It returns the point the source is now completely
// synchronized up to, or the zero time if that point did not move.
type Sync func() (time.Time, error)

// Run performs sync and records its outcome. The returned error is non-nil if
// the sync failed or its outcome could not be recorded.
func Run(db *bun.DB, source string, sync Sync) error {
	ctx := context.Background()
	started := time.Now()

	if err := markStarted(ctx, db, source, started); err != nil {
		logger.WithFields(logrus.Fields{"source": source, "error": err.Error()}).Error("Could not start knowledge source sync")
		return fmt.Errorf("%s: record run start: %w", source, err)
	}

	watermark, syncErr := runRecovering(sync)

	rows, countErr := countRows(ctx, db, source)
	if countErr != nil {
		logger.WithFields(logrus.Fields{"source": source, "error": countErr.Error()}).Warn("Could not count knowledge source rows")
	}

	recordErr := markFinished(ctx, db, source, watermark, syncErr, rows)
	if recordErr != nil {
		recordErr = fmt.Errorf("%s: record run outcome: %w", source, recordErr)
	}

	logOutcome(source, started, watermark, rows, syncErr)
	if syncErr != nil {
		syncErr = fmt.Errorf("%s: %w", source, syncErr)
	}
	return errors.Join(syncErr, recordErr)
}

// Watermark returns the source's watermark, or the zero time if it has none.
func Watermark(db *bun.DB, source string) (time.Time, error) {
	row := knowledge.SourceSync{Source: source}
	err := db.NewSelect().Model(&row).WherePK().Scan(context.Background())
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("read %s watermark: %w", source, err)
	}
	if row.Watermark == nil {
		return time.Time{}, nil
	}
	return *row.Watermark, nil
}

// runRecovering turns a panic in sync into an error so later sources still run.
func runRecovering(sync Sync) (watermark time.Time, err error) {
	defer func() {
		if p := recover(); p != nil {
			watermark, err = time.Time{}, fmt.Errorf("panic: %v", p)
		}
	}()
	return sync()
}

func markStarted(ctx context.Context, db *bun.DB, source string, started time.Time) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO knowledge_source_sync (source, last_run_started_at) VALUES (?, ?)
		ON CONFLICT (source) DO UPDATE SET last_run_started_at = EXCLUDED.last_run_started_at`,
		source, started)
	return err
}

func markFinished(ctx context.Context, db *bun.DB, source string, watermark time.Time, syncErr error, rows *int64) error {
	outcome := knowledge.SourceSyncSuccess
	var lastError *string
	if syncErr != nil {
		outcome = knowledge.SourceSyncFailure
		stored := storableError(syncErr)
		lastError = &stored
	}
	var newWatermark *time.Time
	if !watermark.IsZero() {
		newWatermark = &watermark
	}

	_, err := db.ExecContext(ctx, `
		UPDATE knowledge_source_sync SET
			watermark = COALESCE(?, watermark),
			last_run_finished_at = ?,
			last_outcome = ?,
			last_error = ?,
			row_count = COALESCE(?, row_count)
		WHERE source = ?`,
		newWatermark, time.Now(), outcome, lastError, rows, source)
	return err
}

// countRows counts the source's table, which shares the source's name.
func countRows(ctx context.Context, db *bun.DB, source string) (*int64, error) {
	var rows int64
	err := db.NewSelect().TableExpr("?", bun.Ident(source)).ColumnExpr("count(*)").Scan(ctx, &rows)
	if err != nil {
		return nil, err
	}
	return &rows, nil
}

// storableError makes an error safe and small enough for a text column.
func storableError(err error) string {
	text := strings.ReplaceAll(strings.ToValidUTF8(err.Error(), "?"), "\x00", "")
	if len(text) <= maxStoredErrorLength {
		return text
	}
	return strings.ToValidUTF8(text[:maxStoredErrorLength], "")
}

func logOutcome(source string, started time.Time, watermark time.Time, rows *int64, syncErr error) {
	fields := logrus.Fields{
		"source":           source,
		"outcome":          knowledge.SourceSyncSuccess,
		"duration_seconds": time.Since(started).Seconds(),
	}
	if !watermark.IsZero() {
		fields["watermark"] = watermark.UTC().Format(time.RFC3339)
	}
	if rows != nil {
		fields["row_count"] = *rows
	}
	if syncErr != nil {
		fields["outcome"] = knowledge.SourceSyncFailure
		fields["error"] = storableError(syncErr)
		logger.WithFields(fields).Error("Knowledge source sync failed")
		return
	}
	logger.WithFields(fields).Info("Knowledge source sync finished")
}
