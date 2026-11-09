package datedrestore

import (
	"context"
	"errors"
	"testing"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	"github.com/uptrace/bun"
)

func mark(t *testing.T, db *bun.DB) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), "INSERT INTO knowledge_dated_restore (label) VALUES ('2025-01')"); err != nil {
		t.Fatal(err)
	}
}

func TestUnmarkedDatabaseIsLive(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)

	if err := RefuseMarked(db); err != nil {
		t.Errorf("RefuseMarked: %v", err)
	}
	if err := RequireMarked(db); !errors.Is(err, ErrNotDatedRestore) {
		t.Errorf("RequireMarked = %v, want ErrNotDatedRestore", err)
	}
}

func TestMarkedDatabaseIsADatedRestore(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	mark(t, db)

	if err := RefuseMarked(db); !errors.Is(err, ErrDatedRestore) {
		t.Errorf("RefuseMarked = %v, want ErrDatedRestore", err)
	}
	if err := RequireMarked(db); err != nil {
		t.Errorf("RequireMarked: %v", err)
	}
}

func TestDatabaseWithoutMarkerTableIsUnmarked(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	if _, err := db.ExecContext(context.Background(), "DROP TABLE knowledge_dated_restore"); err != nil {
		t.Fatal(err)
	}

	if err := RefuseMarked(db); err != nil {
		t.Errorf("RefuseMarked: %v", err)
	}
	if err := RequireMarked(db); !errors.Is(err, ErrNotDatedRestore) {
		t.Errorf("RequireMarked = %v, want ErrNotDatedRestore", err)
	}
}
