package pgsql

import (
	"context"
	"fmt"
	"strings"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// cweChunkSize bounds one upsert statement.
const cweChunkSize = 500

// cweColumns are the columns refreshed when a CWE already exists.
var cweColumns = []string{
	"name", "abstraction", "structure", "status", "description", "extended_description",
	"related_weaknesses", "modes_of_introduction", "common_consequences", "detection_methods",
	"potential_mitigations", "taxonomy_mappings", "likelihood_of_exploit", "observed_examples",
	"alternate_terms", "affected_resources", "functional_areas", "categories", "applicable_platforms",
}

// UpdateCWE upserts CWE entries on cwe_id in one transaction.
func UpdateCWE(db *bun.DB, cwes []knowledge.CWEEntry) error {
	assignments := make([]string, len(cweColumns))
	for i, column := range cweColumns {
		assignments[i] = column + " = EXCLUDED." + column
	}
	conflict := "CONFLICT (cwe_id) DO UPDATE SET " + strings.Join(assignments, ", ")

	ctx := context.Background()
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		for start := 0; start < len(cwes); start += cweChunkSize {
			chunk := cwes[start:min(start+cweChunkSize, len(cwes))]
			if _, err := tx.NewInsert().Model(&chunk).On(conflict).Exec(ctx); err != nil {
				return fmt.Errorf("upsert %d CWE entries: %w", len(chunk), err)
			}
		}
		return nil
	})
}
