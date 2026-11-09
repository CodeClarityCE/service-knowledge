package knowledge

import (
	"errors"
	"testing"
)

func TestRunAllRunsEverySourceAndJoinsFailures(t *testing.T) {
	first, third := errors.New("first failed"), errors.New("third failed")
	var ran []string

	err := runAll([]updateStep{
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
	err := runAll([]updateStep{func() error { return nil }})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
