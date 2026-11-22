package epss

import (
	"testing"
)

func TestEpssURL(t *testing.T) {
	if got, want := epssURL(""), "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"; got != want {
		t.Errorf("epssURL(\"\") = %q, want %q", got, want)
	}
	if got, want := epssURL("2024-01-01"), "https://epss.empiricalsecurity.com/epss_scores-2024-01-01.csv.gz"; got != want {
		t.Errorf("epssURL(\"2024-01-01\") = %q, want %q", got, want)
	}
}
