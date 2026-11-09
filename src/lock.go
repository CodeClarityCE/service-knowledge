package knowledge

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
	"github.com/sirupsen/logrus"
	"github.com/uptrace/bun"
)

var logger = sourcesync.NewLogger()

// updateLockKey identifies the knowledge update lock among Postgres advisory locks.
const updateLockKey int64 = 7236154901

// ErrUpdateInProgress means another knowledge update holds the update lock.
var ErrUpdateInProgress = errors.New("another knowledge update is already running")

// WithUpdateLock calls run while holding the knowledge update lock.
// An open transaction holds the lock, which keeps the run on one database connection.
func WithUpdateLock(ctx context.Context, db *bun.DB, run func() error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin knowledge update lock transaction: %w", err)
	}
	// Ending the transaction releases the lock, including after a panic.
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.WithFields(logrus.Fields{"error": err.Error()}).Warn("Releasing the knowledge update lock failed")
		}
	}()

	var acquired bool
	err = tx.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock(?)", updateLockKey).Scan(&acquired)
	if err != nil {
		return fmt.Errorf("acquire knowledge update lock: %w", err)
	}
	if !acquired {
		return ErrUpdateInProgress
	}

	return run()
}
