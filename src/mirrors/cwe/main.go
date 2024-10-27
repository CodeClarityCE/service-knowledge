// Package cwe downloads CWEs from MITRE and updates the CWEs in the knowledge database graph.
package cwe

import (
	"log"

	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	"github.com/uptrace/bun"
)

// Update is a function that updates the CWEs in the knowledge database graph.
// It downloads the CWEs from the graph, and then updates them.
func Update(db *bun.DB) error {
	log.Println("Start updating CWEs")
	cwes, err := downloadCWEs()
	if err != nil {
		return err
	}
	err = pgsql.UpdateCWE(db, cwes)
	if err != nil {
		return err
	}
	return nil
}
