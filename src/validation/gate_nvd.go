package validation

import (
	"context"
	"fmt"
	"math"

	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
)

func init() {
	registerSourceChecks(knowledge.SourceNVD, upstreamTotalCheck(knowledge.SourceNVD), nvdConfigurationsCheck)
}

// nvdConfigurationsCheck passes when at most KNOWLEDGE_GATE_NVD_MISSING_CONFIGURATIONS_PERCENT of
// active Analyzed or Modified CVEs lack configurations, since vuln-finder matches products from them.
// NVD itself serves a few old Modified CVEs without any.
func nvdConfigurationsCheck(ctx context.Context, g Gate) Check {
	const name = "nvd.configurations"
	const analyzed = `retired_at IS NULL
		AND "vulnStatus" IN ('` + pgsql.NvdStatusAnalyzed + `', '` + pgsql.NvdStatusModified + `')`
	percent := envFloat("KNOWLEDGE_GATE_NVD_MISSING_CONFIGURATIONS_PERCENT", defaultMissingConfigurationsPercent)
	total, err := countWhere(ctx, g.Knowledge, knowledge.SourceNVD, analyzed)
	if err != nil {
		return failed(name, nil, err)
	}
	allowed := int64(math.Floor(float64(total) * percent / 100))
	expected := fmt.Sprintf("at most %d (%g%% of %d)", allowed, percent, total)
	missing, err := countWhere(ctx, g.Knowledge, knowledge.SourceNVD, analyzed+`
		AND (configurations IS NULL OR jsonb_typeof(configurations) <> 'array' OR jsonb_array_length(configurations) = 0)`)
	if err != nil {
		return failed(name, expected, err)
	}
	check := Check{Name: name, Expected: expected, Actual: missing, Pass: missing <= allowed}
	if !check.Pass {
		check.Detail = "Analyzed or Modified CVEs without configurations"
	}
	return check
}
