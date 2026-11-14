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

var logger = NewLogger()

// NewLogger returns a logger that writes structured JSON to stderr.
func NewLogger() *logrus.Logger {
	return &logrus.Logger{
		Out:       defaultLogOutput,
		Formatter: &logrus.JSONFormatter{},
		Hooks:     make(logrus.LevelHooks),
		Level:     logrus.InfoLevel,
	}
}

// Sync does one source's work. It returns the point the source is now completely
// synchronized up to. Run ignores that point when the sync also returns an error.
type Sync func() (time.Time, error)

// Result is what one successful sync of a source saw.
type Result struct {
	// Watermark is the point the source is now completely synchronized up to.
	Watermark time.Time
	// UpstreamTotal is how many records upstream holds. Leave it nil when the run saw
	// only part of upstream, such as an incremental window, to keep the recorded total.
	UpstreamTotal *int64
}

// CountedSync does one source's work and reports what upstream held.
type CountedSync func() (Result, error)

// ErrNoUpstreamRecords means upstream offered no records, so the source fails instead of syncing nothing.
var ErrNoUpstreamRecords = errors.New("upstream has no records")

// Total returns n as an upstream total.
func Total(n int) *int64 {
	total := int64(n)
	return &total
}

// DistinctTotal returns the number of different ids as an upstream total.
func DistinctTotal(ids []string) *int64 {
	distinct := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		distinct[id] = struct{}{}
	}
	return Total(len(distinct))
}

// Run performs sync and records its outcome. The returned error is non-nil if
// the sync failed or its outcome could not be recorded.
func Run(db *bun.DB, source string, sync Sync) error {
	return RunCounted(db, source, func() (Result, error) {
		watermark, err := sync()
		return Result{Watermark: watermark}, err
	})
}

// RunCounted is Run for a sync that also reports the upstream total, which is
// recorded only on success. A total of zero fails the source.
func RunCounted(db *bun.DB, source string, sync CountedSync) error {
	ctx := context.Background()
	started := time.Now()

	if err := markStarted(ctx, db, source, started); err != nil {
		logger.WithFields(logrus.Fields{"source": source, "error": err.Error()}).Error("Could not start knowledge source sync")
		return fmt.Errorf("%s: record run start: %w", source, err)
	}

	result, syncErr := runRecovering(sync)
	if syncErr == nil && result.UpstreamTotal != nil && *result.UpstreamTotal == 0 {
		syncErr = ErrNoUpstreamRecords
	}
	if syncErr != nil {
		result = Result{}
	}

	rows, countErr := countRows(ctx, db, source)
	if countErr != nil {
		logger.WithFields(logrus.Fields{"source": source, "error": countErr.Error()}).Warn("Could not count knowledge source rows")
	}

	recordErr := markFinished(ctx, db, source, result, syncErr, rows)
	if recordErr != nil {
		recordErr = fmt.Errorf("%s: record run outcome: %w", source, recordErr)
	}

	logOutcome(source, started, result, rows, syncErr)
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

// SetWatermark sets only the source's watermark, creating its row if needed.
func SetWatermark(db *bun.DB, source string, watermark time.Time) error {
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO knowledge_source_sync (source, watermark) VALUES (?, ?)
		ON CONFLICT (source) DO UPDATE SET watermark = EXCLUDED.watermark`,
		source, watermark)
	if err != nil {
		return fmt.Errorf("write %s watermark: %w", source, err)
	}
	return nil
}

// ResetWatermark clears the source's watermark and bulk progress, so its next sync is a full fetch.
func ResetWatermark(db *bun.DB, source string) error {
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO knowledge_source_sync (source) VALUES (?)
		ON CONFLICT (source) DO UPDATE SET watermark = NULL, bulk_completed_at = NULL`, source)
	if err != nil {
		return fmt.Errorf("reset %s watermark: %w", source, err)
	}
	return nil
}

// BulkCompletedAt returns the time a finished bulk import is current to while
// its enrichment is pending, or the zero time if none is pending.
func BulkCompletedAt(db *bun.DB, source string) (time.Time, error) {
	var completedAt sql.NullTime
	err := db.NewSelect().
		Table("knowledge_source_sync").
		Column("bulk_completed_at").
		Where("source = ?", source).
		Scan(context.Background(), &completedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, fmt.Errorf("read %s bulk completion: %w", source, err)
	}
	return completedAt.Time, nil
}

// SetBulkCompletedAt records only that a bulk import is done and enrichment is pending.
func SetBulkCompletedAt(db *bun.DB, source string, completedAt time.Time) error {
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO knowledge_source_sync (source, bulk_completed_at) VALUES (?, ?)
		ON CONFLICT (source) DO UPDATE SET bulk_completed_at = EXCLUDED.bulk_completed_at`,
		source, completedAt)
	if err != nil {
		return fmt.Errorf("write %s bulk completion: %w", source, err)
	}
	return nil
}

// SetConfigLast writes one *_last column, so it cannot overwrite the other sources' columns.
func SetConfigLast(configDB *bun.DB, column string, syncedAt time.Time) error {
	result, err := configDB.NewUpdate().
		Table("config").
		Set("? = ?", bun.Ident(column), syncedAt).
		Where("id = (SELECT id FROM config LIMIT 1)").
		Exec(context.Background())
	if err != nil {
		return fmt.Errorf("write %s: %w", column, err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return fmt.Errorf("no config found")
	}
	return nil
}

// runRecovering turns a panic in sync into an error so later sources still run.
func runRecovering(sync CountedSync) (result Result, err error) {
	defer func() {
		if p := recover(); p != nil {
			result, err = Result{}, fmt.Errorf("panic: %v", p)
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

func markFinished(ctx context.Context, db *bun.DB, source string, result Result, syncErr error, rows *int64) error {
	outcome := knowledge.SourceSyncSuccess
	var lastError *string
	if syncErr != nil {
		outcome = knowledge.SourceSyncFailure
		stored := storableError(syncErr)
		lastError = &stored
	}
	var newWatermark *time.Time
	if !result.Watermark.IsZero() {
		newWatermark = &result.Watermark
	}

	_, err := db.ExecContext(ctx, `
		UPDATE knowledge_source_sync SET
			watermark = COALESCE(?, watermark),
			last_run_finished_at = ?,
			last_outcome = ?,
			last_error = ?,
			row_count = COALESCE(?, row_count),
			upstream_total = COALESCE(?, upstream_total),
			bulk_completed_at = CASE WHEN ? THEN NULL ELSE bulk_completed_at END
		WHERE source = ?`,
		newWatermark, time.Now(), outcome, lastError, rows, result.UpstreamTotal, syncErr == nil, source)
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

func logOutcome(source string, started time.Time, result Result, rows *int64, syncErr error) {
	fields := logrus.Fields{
		"source":           source,
		"outcome":          knowledge.SourceSyncSuccess,
		"duration_seconds": time.Since(started).Seconds(),
	}
	if !result.Watermark.IsZero() {
		fields["watermark"] = result.Watermark.UTC().Format(time.RFC3339)
	}
	if result.UpstreamTotal != nil {
		fields["upstream_total"] = *result.UpstreamTotal
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
