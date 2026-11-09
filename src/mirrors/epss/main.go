package epss

import (
	"log"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// Update imports the current EPSS scores and removes CVEs the file no longer contains.
func Update(db *bun.DB) error {
	return sourcesync.Run(db, knowledge.SourceEPSS, func() (time.Time, error) {
		syncedAt := time.Now()
		cves, err := importScores(db, "")
		if err != nil {
			return time.Time{}, err
		}
		if err := pgsql.ReconcileEPSS(db, cves); err != nil {
			return time.Time{}, err
		}
		return syncedAt, nil
	})
}

// UpdateAsOf imports the EPSS scores published on the given date (YYYY-MM-DD).
// A dated file is a partial view, so it never removes stored CVEs.
func UpdateAsOf(db *bun.DB, date string) error {
	_, err := importScores(db, date)
	return err
}

// importScores stores a fully parsed scores file and returns its CVEs.
func importScores(db *bun.DB, date string) ([]string, error) {
	log.Println("Start updating EPSS scores")
	epss, err := downloadEPSS(epssURL(date))
	if err != nil {
		return nil, err
	}
	if err := pgsql.UpdateEPSS(db, epss); err != nil {
		return nil, err
	}
	cves := make([]string, len(epss))
	for i, score := range epss {
		cves[i] = score.CVE
	}
	return cves, nil
}

// epssURL returns the download URL for the EPSS scores file: the current file
// when date is empty, or the dated snapshot (YYYY-MM-DD) otherwise.
func epssURL(date string) string {
	if date == "" {
		return baseURL + "epss_scores-current.csv.gz"
	}
	return baseURL + "epss_scores-" + date + ".csv.gz"
}
