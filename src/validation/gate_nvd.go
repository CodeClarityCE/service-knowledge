package validation

import (
	"context"

	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
)

func init() {
	registerSourceChecks(knowledge.SourceNVD, upstreamTotalCheck(knowledge.SourceNVD), nvdConfigurationsCheck)
}

// nvdConfigurationsCheck passes when every active Analyzed or Modified CVE has configurations,
// since vuln-finder matches products from them.
func nvdConfigurationsCheck(ctx context.Context, g Gate) Check {
	const name = "nvd.configurations"
	missing, err := countWhere(ctx, g.Knowledge, knowledge.SourceNVD, `retired_at IS NULL
		AND "vulnStatus" IN ('`+pgsql.NvdStatusAnalyzed+`', '`+pgsql.NvdStatusModified+`')
		AND (configurations IS NULL OR jsonb_typeof(configurations) <> 'array' OR jsonb_array_length(configurations) = 0)`)
	if err != nil {
		return failed(name, 0, err)
	}
	check := Check{Name: name, Expected: 0, Actual: missing, Pass: missing == 0}
	if !check.Pass {
		check.Detail = "Analyzed or Modified CVEs without configurations"
	}
	return check
}
