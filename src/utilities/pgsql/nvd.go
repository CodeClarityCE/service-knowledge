package pgsql

import (
	"context"
	"fmt"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// nvdItemsToWrite drops rejected and deferred items and keeps the last copy of each CVE,
// because one upsert cannot touch the same row twice.
func nvdItemsToWrite(nvd []knowledge.NVDItem) []knowledge.NVDItem {
	seen := make(map[string]int, len(nvd))
	items := make([]knowledge.NVDItem, 0, len(nvd))

	for _, item := range nvd {
		if item.VulnStatus == "Rejected" || item.VulnStatus == "Deferred" {
			continue
		}
		if idx, exists := seen[item.NVDId]; exists {
			items[idx] = item
		} else {
			seen[item.NVDId] = len(items)
			items = append(items, item)
		}
	}

	return items
}

// UpdateNvd upserts a page of NVD items on nvd_id in one transaction.
func UpdateNvd(db *bun.DB, nvd []knowledge.NVDItem) error {
	items := nvdItemsToWrite(nvd)
	if len(items) == 0 {
		return nil
	}

	ctx := context.Background()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for NVD update: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.NewInsert().
		Model(&items).
		On("CONFLICT (nvd_id) DO UPDATE SET \"sourceIdentifier\" = EXCLUDED.\"sourceIdentifier\", published = EXCLUDED.published, \"lastModified\" = EXCLUDED.\"lastModified\", \"vulnStatus\" = EXCLUDED.\"vulnStatus\", descriptions = EXCLUDED.descriptions, vlai_score = EXCLUDED.vlai_score, vlai_confidence = EXCLUDED.vlai_confidence, metrics = EXCLUDED.metrics, weaknesses = EXCLUDED.weaknesses, configurations = EXCLUDED.configurations, \"affectedFlattened\" = EXCLUDED.\"affectedFlattened\", affected = EXCLUDED.affected, \"references\" = EXCLUDED.\"references\"").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to upsert %d NVD items: %w", len(items), err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit NVD update: %w", err)
	}

	return nil
}

// GetNvdUUIDsByNvdIds retrieves the internal UUIDs for a list of NVD IDs.
// Returns a map from nvd_id (string like "CVE-xxx") to internal UUID.
func GetNvdUUIDsByNvdIds(db *bun.DB, nvdIds []string) (map[string]uuid.UUID, error) {
	if len(nvdIds) == 0 {
		return make(map[string]uuid.UUID), nil
	}

	ctx := context.Background()

	var results []struct {
		Id    uuid.UUID `bun:"id"`
		NvdId string    `bun:"nvd_id"`
	}

	err := db.NewSelect().
		TableExpr("nvd").
		Column("id", "nvd_id").
		Where("nvd_id IN (?)", bun.In(nvdIds)).
		Scan(ctx, &results)

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve NVD UUIDs: %w", err)
	}

	result := make(map[string]uuid.UUID, len(results))
	for _, r := range results {
		result[r.NvdId] = r.Id
	}

	return result, nil
}
