package pgsql

import (
	"context"
	"fmt"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// NVD vulnStatus values with special handling. Only Analyzed and Modified CVEs are matched.
const (
	NvdStatusRejected = "Rejected"
	NvdStatusDeferred = "Deferred"
	NvdStatusAnalyzed = "Analyzed"
	NvdStatusModified = "Modified"
)

// nvdItemsToWrite keeps the last copy of each CVE, because one upsert cannot touch the same row twice.
// It splits off rejected items, which are retired rather than updated.
func nvdItemsToWrite(nvd []knowledge.NVDItem) (items, rejected []knowledge.NVDItem) {
	seen := make(map[string]int, len(nvd))
	unique := make([]knowledge.NVDItem, 0, len(nvd))
	for _, item := range nvd {
		if idx, exists := seen[item.NVDId]; exists {
			unique[idx] = item
		} else {
			seen[item.NVDId] = len(unique)
			unique = append(unique, item)
		}
	}
	for _, item := range unique {
		if item.VulnStatus == NvdStatusRejected {
			rejected = append(rejected, item)
		} else {
			items = append(items, item)
		}
	}
	return items, rejected
}

// UpdateNvd stores a page of NVD items on nvd_id in one transaction. Rejected CVEs are
// stored if new, otherwise keep their content, and are retired with their rejection date.
func UpdateNvd(db *bun.DB, nvd []knowledge.NVDItem) error {
	items, rejected := nvdItemsToWrite(nvd)
	if len(items) == 0 && len(rejected) == 0 {
		return nil
	}
	normalizeNvdDates(items)
	normalizeNvdDates(rejected)
	ctx := context.Background()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for NVD update: %w", err)
	}
	defer tx.Rollback()

	if len(items) > 0 {
		_, err = tx.NewInsert().
			Model(&items).
			On("CONFLICT (nvd_id) DO UPDATE SET \"sourceIdentifier\" = EXCLUDED.\"sourceIdentifier\", published = EXCLUDED.published, \"lastModified\" = EXCLUDED.\"lastModified\", \"vulnStatus\" = EXCLUDED.\"vulnStatus\", descriptions = EXCLUDED.descriptions, vlai_score = EXCLUDED.vlai_score, vlai_confidence = EXCLUDED.vlai_confidence, metrics = EXCLUDED.metrics, weaknesses = EXCLUDED.weaknesses, configurations = EXCLUDED.configurations, \"affectedFlattened\" = EXCLUDED.\"affectedFlattened\", affected = EXCLUDED.affected, \"references\" = EXCLUDED.\"references\"").
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("failed to upsert %d NVD items: %w", len(items), err)
		}
		ids := make([]string, len(items))
		for i, item := range items {
			ids[i] = item.NVDId
		}
		if err := clearRetirement(ctx, tx, "nvd", "nvd_id", ids); err != nil {
			return fmt.Errorf("reactivate NVD items: %w", err)
		}
	}

	if len(rejected) > 0 {
		// Returning nothing, since skipped rows would shift bun's scan of returned ids onto the wrong items.
		_, err = tx.NewInsert().Model(&rejected).On("CONFLICT (nvd_id) DO NOTHING").Returning("NULL").Exec(ctx)
		if err != nil {
			return fmt.Errorf("failed to insert %d rejected NVD items: %w", len(rejected), err)
		}
		if err := retireRejectedNvd(ctx, tx, rejected); err != nil {
			return err
		}
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
