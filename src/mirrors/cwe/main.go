// Package cwe downloads CWEs from MITRE and updates the CWEs in the knowledge database graph.
package cwe

import (
	"log"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// Update is a function that updates the CWEs in the knowledge database graph.
// It downloads the CWEs from the graph, and then updates them.
func Update(db *bun.DB) error {
	return sourcesync.Run(db, knowledge.SourceCWE, func() (time.Time, error) {
		log.Println("Start updating CWEs")
		syncedAt := time.Now()
		cwes, err := downloadCWEs()
		if err != nil {
			return time.Time{}, err
		}
		if err := pgsql.UpdateCWE(db, cwes); err != nil {
			return time.Time{}, err
		}
		return syncedAt, nil
	})
}
