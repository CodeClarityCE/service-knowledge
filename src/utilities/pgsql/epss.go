package pgsql

import (
	"context"
	"fmt"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// epssChunkSize bounds one upsert statement.
const epssChunkSize = 5000

// UpdateEPSS upserts scores on cve in one transaction, keeping the last copy of a repeated CVE.
func UpdateEPSS(db *bun.DB, epssScores []knowledge.EPSS) error {
	byCVE := make(map[string]int, len(epssScores))
	unique := make([]knowledge.EPSS, 0, len(epssScores))
	for _, score := range epssScores {
		if index, repeated := byCVE[score.CVE]; repeated {
			unique[index] = score
			continue
		}
		byCVE[score.CVE] = len(unique)
		unique = append(unique, score)
	}
	if len(unique) == 0 {
		return nil
	}

	ctx := context.Background()
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		for start := 0; start < len(unique); start += epssChunkSize {
			chunk := unique[start:min(start+epssChunkSize, len(unique))]
			_, err := tx.NewInsert().
				Model(&chunk).
				On("CONFLICT (cve) DO UPDATE SET score = EXCLUDED.score, percentile = EXCLUDED.percentile, score_date = EXCLUDED.score_date").
				Exec(ctx)
			if err != nil {
				return fmt.Errorf("upsert %d EPSS scores: %w", len(chunk), err)
			}
		}
		return nil
	})
}
