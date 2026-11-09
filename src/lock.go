package knowledge

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"

	"github.com/uptrace/bun"
)

// updateLockKey identifies the knowledge update lock among Postgres advisory locks.
const updateLockKey int64 = 7236154901

// ErrUpdateInProgress means another knowledge update holds the update lock.
var ErrUpdateInProgress = errors.New("another knowledge update is already running")

// WithUpdateLock calls run while holding the knowledge update lock.
// The lock lives in an open transaction, so it holds its connection through pgbouncer transaction pooling.
func WithUpdateLock(ctx context.Context, db *bun.DB, run func() error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin knowledge update lock transaction: %w", err)
	}
	// Ending the transaction releases the lock, including after a panic.
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			log.Printf("Warning: releasing the knowledge update lock failed: %v", err)
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
