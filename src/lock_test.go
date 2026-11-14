package knowledge

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// openLockTestDB connects to KNOWLEDGE_LOCK_TEST_DSN, which may point at Postgres or pgbouncer.
func openLockTestDB(t *testing.T) *bun.DB {
	t.Helper()
	dsn := os.Getenv("KNOWLEDGE_LOCK_TEST_DSN")
	if dsn == "" {
		t.Skip("KNOWLEDGE_LOCK_TEST_DSN is not set")
	}
	db := bun.NewDB(sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn))), pgdialect.New())
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func noop() error { return nil }

func TestUpdateLockBlocksOverlappingRuns(t *testing.T) {
	holder, other := openLockTestDB(t), openLockTestDB(t)
	ctx := context.Background()

	err := WithUpdateLock(ctx, holder, func() error {
		// A separate client and another query on the holder's pool must not disturb the lock.
		if err := holder.PingContext(ctx); err != nil {
			return err
		}
		ran := false
		overlap := WithUpdateLock(ctx, other, func() error { ran = true; return nil })
		if !errors.Is(overlap, ErrUpdateInProgress) {
			t.Errorf("overlapping run returned %v, want ErrUpdateInProgress", overlap)
		}
		if ran {
			t.Error("overlapping run should not have started")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := WithUpdateLock(ctx, other, noop); err != nil {
		t.Fatalf("lock should be free after the run finished: %v", err)
	}
}

func TestUpdateLockIsReleasedAfterFailedRun(t *testing.T) {
	db := openLockTestDB(t)
	ctx := context.Background()

	failure := errors.New("source failed")
	if err := WithUpdateLock(ctx, db, func() error { return failure }); !errors.Is(err, failure) {
		t.Fatalf("got %v, want the run's own error", err)
	}
	if err := WithUpdateLock(ctx, db, noop); err != nil {
		t.Fatalf("lock should be free after a failed run: %v", err)
	}
}

func TestUpdateLockIsReleasedAfterPanic(t *testing.T) {
	db := openLockTestDB(t)
	ctx := context.Background()

	func() {
		defer func() { _ = recover() }()
		_ = WithUpdateLock(ctx, db, func() error { panic("update crashed") })
	}()
	if err := WithUpdateLock(ctx, db, noop); err != nil {
		t.Fatalf("lock should be free after a panic: %v", err)
	}
}

func TestUpdateLockIsReleasedWhenHolderDies(t *testing.T) {
	holder, other := openLockTestDB(t), openLockTestDB(t)
	ctx := context.Background()

	_ = WithUpdateLock(ctx, holder, func() error { return holder.Close() })

	deadline := time.Now().Add(5 * time.Second)
	for {
		err := WithUpdateLock(ctx, other, noop)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("lock still held after the holder's connection closed: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
