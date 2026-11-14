package knowledge

import (
	"context"
	"errors"
	"testing"

	"github.com/CodeClarityCE/service-knowledge/src/datedrestore"
	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
)

func TestRunAllRunsEverySourceAndJoinsFailures(t *testing.T) {
	first, third := errors.New("first failed"), errors.New("third failed")
	var ran []string

	err := runAll([]func() error{
		func() error { ran = append(ran, "a"); return first },
		func() error { ran = append(ran, "b"); return nil },
		func() error { ran = append(ran, "c"); return third },
	})

	if len(ran) != 3 {
		t.Errorf("ran %v, want every step", ran)
	}
	if !errors.Is(err, first) || !errors.Is(err, third) {
		t.Errorf("err = %v, want both failures joined", err)
	}
}

func TestRunAllSucceedsWhenEverySourceSucceeds(t *testing.T) {
	err := runAll([]func() error{func() error { return nil }})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidationRunsAfterAFailedUpdate(t *testing.T) {
	updateErr, validationErr := errors.New("nvd failed"), errors.New("validation failed")

	err := updateThenValidate(func() error { return updateErr }, func() error { return validationErr })

	if !errors.Is(err, updateErr) || !errors.Is(err, validationErr) {
		t.Errorf("err = %v, want both failures joined", err)
	}
}

func TestValidationSkippedWhenUpdateRefusesADatedRestore(t *testing.T) {
	validated := false

	err := updateThenValidate(func() error { return datedrestore.ErrDatedRestore }, func() error { validated = true; return nil })

	if validated {
		t.Error("validation should not run on a marked database")
	}
	if !errors.Is(err, datedrestore.ErrDatedRestore) {
		t.Errorf("err = %v", err)
	}
}

func TestUpdateRefusesAMarkedDatabaseBeforeTouchingAnySource(t *testing.T) {
	db := testhelper.SetupSyncTestDB(t)
	if _, err := db.ExecContext(context.Background(), "INSERT INTO knowledge_dated_restore (label) VALUES ('2025-01')"); err != nil {
		t.Fatal(err)
	}

	err := Update(db, nil, nil)

	if !errors.Is(err, datedrestore.ErrDatedRestore) {
		t.Errorf("Update = %v, want ErrDatedRestore", err)
	}
}
