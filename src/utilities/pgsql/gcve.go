package pgsql

import (
	"context"
	"database/sql"
	"fmt"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// deduplicateGcveItems removes duplicate GCVE IDs within a batch, keeping the last
// occurrence. This prevents PostgreSQL's "ON CONFLICT DO UPDATE command cannot affect
// row a second time" error when the same CVE appears multiple times in one batch
// (e.g. from the /api/last incremental endpoint).
func deduplicateGcveItems(items []knowledge.GCVEItem) []knowledge.GCVEItem {
	seen := make(map[string]int, len(items))
	result := make([]knowledge.GCVEItem, 0, len(items))

	for _, item := range items {
		if idx, exists := seen[item.GCVEId]; exists {
			result[idx] = item // overwrite with latest
		} else {
			seen[item.GCVEId] = len(result)
			result = append(result, item)
		}
	}

	return result
}

// BatchUpdateGcve performs efficient batch upsert operations for multiple GCVE records.
func BatchUpdateGcve(db *bun.DB, items []knowledge.GCVEItem) error {
	if len(items) == 0 {
		return nil
	}

	items = deduplicateGcveItems(items)

	ctx := context.Background()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for batch GCVE update: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.NewInsert().
		Model(&items).
		On("CONFLICT (gcve_id) DO UPDATE SET cve_id = EXCLUDED.cve_id, data_version = EXCLUDED.data_version, state = EXCLUDED.state, date_published = EXCLUDED.date_published, date_updated = EXCLUDED.date_updated, assigner_org_id = EXCLUDED.assigner_org_id, descriptions = EXCLUDED.descriptions, affected = EXCLUDED.affected, affected_flattened = EXCLUDED.affected_flattened, metrics = EXCLUDED.metrics, problem_types = EXCLUDED.problem_types, \"references\" = EXCLUDED.\"references\", adp_enrichments = EXCLUDED.adp_enrichments, cwes = EXCLUDED.cwes, vlai_score = EXCLUDED.vlai_score, vlai_confidence = EXCLUDED.vlai_confidence").
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to batch upsert %d GCVE records: %w", len(items), err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction for batch GCVE update: %w", err)
	}

	return nil
}

// GetGcveByID retrieves a GCVE record by its GCVE ID.
func GetGcveByID(db *bun.DB, gcveId string) (*knowledge.GCVEItem, error) {
	ctx := context.Background()

	gcve := &knowledge.GCVEItem{}
	err := db.NewSelect().
		Model(gcve).
		Where("gcve_id = ?", gcveId).
		Scan(ctx)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, err
		}
		return nil, fmt.Errorf("failed to retrieve GCVE record with ID %s: %w", gcveId, err)
	}

	return gcve, nil
}

// GetGcveUUIDsByGcveIds retrieves the internal UUIDs for a list of GCVE IDs.
func GetGcveUUIDsByGcveIds(db *bun.DB, gcveIds []string) (map[string]uuid.UUID, error) {
	if len(gcveIds) == 0 {
		return make(map[string]uuid.UUID), nil
	}

	ctx := context.Background()

	var results []struct {
		Id     uuid.UUID `bun:"id"`
		GcveId string    `bun:"gcve_id"`
	}

	err := db.NewSelect().
		TableExpr("gcve").
		Column("id", "gcve_id").
		Where("gcve_id IN (?)", bun.In(gcveIds)).
		Scan(ctx, &results)

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve GCVE UUIDs: %w", err)
	}

	result := make(map[string]uuid.UUID, len(results))
	for _, r := range results {
		result[r.GcveId] = r.Id
	}

	return result, nil
}

// deduplicateGcvePackageVulnerabilities removes duplicate entries for GCVE-based vulnerabilities.
func deduplicateGcvePackageVulnerabilities(items []knowledge.PackageVulnerability) []knowledge.PackageVulnerability {
	seen := make(map[string]int)
	result := make([]knowledge.PackageVulnerability, 0, len(items))

	for _, item := range items {
		if item.GcveId == nil {
			continue
		}
		key := fmt.Sprintf("%s|%s|%s", item.PackageName, item.PackageEcosystem, item.GcveId.String())
		if idx, exists := seen[key]; exists {
			result[idx] = item
		} else {
			seen[key] = len(result)
			result = append(result, item)
		}
	}

	return result
}

// BatchInsertGcvePackageVulnerabilities inserts GCVE-based package-vulnerability links.
func BatchInsertGcvePackageVulnerabilities(db *bun.DB, items []knowledge.PackageVulnerability) error {
	if len(items) == 0 {
		return nil
	}

	items = deduplicateGcvePackageVulnerabilities(items)
	if len(items) == 0 {
		return nil
	}

	ctx := context.Background()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.NewInsert().
		Model(&items).
		On("CONFLICT (package_name, package_ecosystem, gcve_id) WHERE gcve_id IS NOT NULL DO NOTHING").
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to batch insert %d GCVE package vulnerability records: %w", len(items), err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
