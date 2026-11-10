package validation

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
)

// defaultEPSSMaxScoreAgeDays is how many days the EPSS score date may lag the gate.
const defaultEPSSMaxScoreAgeDays = 2

func init() {
	registerSourceChecks(knowledge.SourceEPSS, epssScoreDateCheck)
}

// epssScoreDateCheck passes when every EPSS row has a score date within
// KNOWLEDGE_GATE_EPSS_MAX_SCORE_AGE_DAYS calendar days of the gate.
func epssScoreDateCheck(ctx context.Context, g Gate) Check {
	const name = "epss.score_date"
	maxAge := envFloat("KNOWLEDGE_GATE_EPSS_MAX_SCORE_AGE_DAYS", defaultEPSSMaxScoreAgeDays)
	expected := fmt.Sprintf("within %g days of %s", maxAge, g.Now.UTC().Format(time.DateOnly))
	var oldest sql.NullString
	var undated int64
	err := g.Knowledge.QueryRowContext(ctx,
		"SELECT min(score_date)::text, count(*) FILTER (WHERE score_date IS NULL) FROM epss").Scan(&oldest, &undated)
	if err != nil {
		return failed(name, expected, err)
	}
	if !oldest.Valid || undated > 0 {
		return Check{Name: name, Expected: expected, Actual: nil, Pass: false, Detail: "EPSS rows have no score date"}
	}
	scored, err := time.Parse(time.DateOnly, oldest.String)
	if err != nil {
		return failed(name, expected, err)
	}
	ageDays := g.Now.UTC().Truncate(24*time.Hour).Sub(scored).Hours() / 24
	check := Check{Name: name, Expected: expected, Actual: oldest.String, Pass: ageDays <= maxAge}
	if !check.Pass {
		check.Detail = fmt.Sprintf("the oldest EPSS score is %g days old", ageDays)
	}
	return check
}
