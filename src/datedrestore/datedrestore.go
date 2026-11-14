// Package datedrestore reads the marker that identifies a dated restore of the knowledge database.
package datedrestore

import (
	"context"
	"errors"
	"fmt"

	"github.com/uptrace/bun"
)

var (
	// ErrDatedRestore means the database is a marked dated restore, so updates are refused.
	ErrDatedRestore = errors.New("knowledge database is a marked dated restore")
	// ErrNotDatedRestore means the database is not a marked dated restore.
	ErrNotDatedRestore = errors.New("knowledge database is not a marked dated restore")
)

// marked reports whether the marker row exists. A database without the marker table has none.
func marked(ctx context.Context, db *bun.DB) (bool, error) {
	var isMarked bool
	err := db.QueryRowContext(ctx, `
		SELECT to_regclass('knowledge_dated_restore') IS NOT NULL`).Scan(&isMarked)
	if err != nil || !isMarked {
		return false, err
	}
	err = db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM knowledge_dated_restore)").Scan(&isMarked)
	return isMarked, err
}

// RefuseMarked returns ErrDatedRestore when the database is a marked dated restore.
func RefuseMarked(db *bun.DB) error {
	isMarked, err := marked(context.Background(), db)
	if err != nil {
		return fmt.Errorf("read dated restore marker: %w", err)
	}
	if isMarked {
		return ErrDatedRestore
	}
	return nil
}

// RequireMarked returns ErrNotDatedRestore unless the database is a marked dated restore.
func RequireMarked(db *bun.DB) error {
	isMarked, err := marked(context.Background(), db)
	if err != nil {
		return fmt.Errorf("read dated restore marker: %w", err)
	}
	if !isMarked {
		return ErrNotDatedRestore
	}
	return nil
}
