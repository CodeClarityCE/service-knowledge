package epss

import (
	"log"

	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	"github.com/uptrace/bun"
)

// Update is a function that updates the CWEs in the knowledge database graph.
// It downloads the CWEs from the graph, and then updates them.
func Update(db *bun.DB) error {
	log.Println("Start updating EPSS scores")
	epss, err := downloadEPSS("https://epss.empiricalsecurity.com/epss_scores-current.csv.gz")
	if err != nil {
		return err
	}
	err = pgsql.UpdateEPSS(db, epss)
	if err != nil {
		return err
	}
	return nil
}
