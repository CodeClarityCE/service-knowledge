package validation

import (
	"context"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
)

func init() {
	registerSourceChecks(knowledge.SourceOSV,
		upstreamTotalCheck(knowledge.SourceOSV),
		osvLinksCheck("npm"),
		osvLinksCheck("packagist"),
		osvMaliciousCheck,
	)
}

// osvLinksCheck passes when the ecosystem has package links to active OSV vulnerabilities.
// Links to malicious package advisories do not count, so they cannot hide a missing ecosystem.
func osvLinksCheck(ecosystem string) SourceCheck {
	return func(ctx context.Context, g Gate) Check {
		name := "osv.links." + ecosystem
		var links int64
		err := g.Knowledge.QueryRowContext(ctx, `
			SELECT count(*) FROM package_vulnerability link
			JOIN osv ON osv.id = link.osv_id
			WHERE link.package_ecosystem = ? AND osv.kind = ? AND osv.retired_at IS NULL`,
			ecosystem, knowledge.AdvisoryKindVulnerability).Scan(&links)
		if err != nil {
			return failed(name, "> 0", err)
		}
		check := Check{Name: name, Expected: "> 0", Actual: links, Pass: links > 0}
		if !check.Pass {
			check.Detail = "no " + ecosystem + " package links to OSV vulnerabilities"
		}
		return check
	}
}

// osvMaliciousCheck reports active malicious package advisories apart from osv.rows.
// It only fails when the count cannot be read.
func osvMaliciousCheck(ctx context.Context, g Gate) Check {
	const name = "osv.malicious"
	const expected = "reported, not counted in osv.rows"
	malicious, err := countWhere(ctx, g.Knowledge, knowledge.SourceOSV, "retired_at IS NULL AND kind = 'malicious'")
	if err != nil {
		return failed(name, expected, err)
	}
	return Check{Name: name, Expected: expected, Actual: malicious, Pass: true}
}
