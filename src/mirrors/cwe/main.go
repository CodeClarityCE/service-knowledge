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
	return sourcesync.RunCounted(db, knowledge.SourceCWE, func() (sourcesync.Result, error) {
		log.Println("Start updating CWEs")
		syncedAt := time.Now()
		cwes, err := downloadCWEs()
		if err != nil {
			return sourcesync.Result{}, err
		}
		if err := pgsql.UpdateCWE(db, cwes); err != nil {
			return sourcesync.Result{}, err
		}
		ids := make([]string, len(cwes))
		for i, entry := range cwes {
			ids[i] = entry.CWEId
		}
		if err := pgsql.ReconcileCWE(db, ids); err != nil {
			return sourcesync.Result{}, err
		}
		// Each weakness upstream lists is one stored CWE.
		return sourcesync.Result{Watermark: syncedAt, UpstreamTotal: sourcesync.Total(len(cwes))}, nil
	})
}

// UseUpstream points the mirror at another CWE catalog URL and returns a function that undoes it.
func UseUpstream(url string) (restore func()) {
	original := catalogURL
	catalogURL = url
	return func() { catalogURL = original }
}
