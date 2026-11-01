package epss

import (
	"log"

	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	"github.com/uptrace/bun"
)

// Update is a function that updates the CWEs in the knowledge database graph.
// It downloads the CWEs from the graph, and then updates them.
func Update(db *bun.DB) error {
	return UpdateAsOf(db, "")
}

// UpdateAsOf imports the EPSS scores published on the given date (YYYY-MM-DD).
// An empty date imports the current scores, identical to Update.
func UpdateAsOf(db *bun.DB, date string) error {
	log.Println("Start updating EPSS scores")
	epss, err := downloadEPSS(epssURL(date))
	if err != nil {
		return err
	}
	err = pgsql.UpdateEPSS(db, epss)
	if err != nil {
		return err
	}
	return nil
}

// epssURL returns the download URL for the EPSS scores file: the current file
// when date is empty, or the dated snapshot (YYYY-MM-DD) otherwise.
func epssURL(date string) string {
	if date == "" {
		return "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
	}
	return "https://epss.empiricalsecurity.com/epss_scores-" + date + ".csv.gz"
}
