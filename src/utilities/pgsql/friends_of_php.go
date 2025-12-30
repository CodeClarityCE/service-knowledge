package pgsql

import (
	"context"
	"fmt"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// UpdateFriendsOfPHP updates or inserts a FriendsOfPHP advisory using an efficient upsert operation
func UpdateFriendsOfPHP(db *bun.DB, advisory knowledge.FriendsOfPHPAdvisory) error {
	ctx := context.Background()

	// Use upsert (INSERT ... ON CONFLICT) for better performance and atomicity
	_, err := db.NewInsert().
		Model(&advisory).
		On("CONFLICT (advisory_id) DO UPDATE SET title = EXCLUDED.title, cve = EXCLUDED.cve, link = EXCLUDED.link, reference = EXCLUDED.reference, composer = EXCLUDED.composer, description = EXCLUDED.description, branches = EXCLUDED.branches, published = EXCLUDED.published, modified = EXCLUDED.modified").
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to upsert FriendsOfPHP advisory with ID %s: %w", advisory.AdvisoryId, err)
	}

	return nil
}

// BatchUpdateFriendsOfPHP performs efficient batch upsert operations for multiple FriendsOfPHP advisories
func BatchUpdateFriendsOfPHP(db *bun.DB, advisories []knowledge.FriendsOfPHPAdvisory) error {
	if len(advisories) == 0 {
		return nil
	}

	ctx := context.Background()

	// Start a transaction for better performance and consistency
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for batch FriendsOfPHP update: %w", err)
	}
	defer tx.Rollback()

	// Use batch insert with ON CONFLICT for maximum efficiency
	_, err = tx.NewInsert().
		Model(&advisories).
		On("CONFLICT (advisory_id) DO UPDATE SET title = EXCLUDED.title, cve = EXCLUDED.cve, link = EXCLUDED.link, reference = EXCLUDED.reference, composer = EXCLUDED.composer, description = EXCLUDED.description, branches = EXCLUDED.branches, published = EXCLUDED.published, modified = EXCLUDED.modified").
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to batch upsert %d FriendsOfPHP advisories: %w", len(advisories), err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction for batch FriendsOfPHP update: %w", err)
	}

	return nil
}

// GetFriendsOfPHPByAdvisoryID retrieves a FriendsOfPHP advisory by its advisory ID
func GetFriendsOfPHPByAdvisoryID(db *bun.DB, advisoryId string) (*knowledge.FriendsOfPHPAdvisory, error) {
	ctx := context.Background()

	advisory := &knowledge.FriendsOfPHPAdvisory{}
	err := db.NewSelect().
		Model(advisory).
		Where("advisory_id = ?", advisoryId).
		Scan(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve FriendsOfPHP advisory with ID %s: %w", advisoryId, err)
	}

	return advisory, nil
}

// GetFriendsOfPHPByPackage retrieves FriendsOfPHP advisories for a specific Composer package
func GetFriendsOfPHPByPackage(db *bun.DB, packageName string) ([]knowledge.FriendsOfPHPAdvisory, error) {
	ctx := context.Background()

	var advisories []knowledge.FriendsOfPHPAdvisory
	err := db.NewSelect().
		Model(&advisories).
		Where("composer = ?", packageName).
		Scan(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve FriendsOfPHP advisories for package %s: %w", packageName, err)
	}

	return advisories, nil
}

// GetAllFriendsOfPHP retrieves all FriendsOfPHP advisories with optional pagination
func GetAllFriendsOfPHP(db *bun.DB, limit, offset int) ([]knowledge.FriendsOfPHPAdvisory, error) {
	ctx := context.Background()

	var advisories []knowledge.FriendsOfPHPAdvisory
	query := db.NewSelect().Model(&advisories)

	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}

	err := query.Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve FriendsOfPHP advisories: %w", err)
	}

	return advisories, nil
}

// GetFriendsOfPhpUUIDsByAdvisoryIds retrieves the internal UUIDs for a list of FriendsOfPHP advisory IDs.
// Returns a map from advisory_id (string) to internal UUID.
func GetFriendsOfPhpUUIDsByAdvisoryIds(db *bun.DB, advisoryIds []string) (map[string]uuid.UUID, error) {
	if len(advisoryIds) == 0 {
		return make(map[string]uuid.UUID), nil
	}

	ctx := context.Background()

	var results []struct {
		Id         uuid.UUID `bun:"id"`
		AdvisoryId string    `bun:"advisory_id"`
	}

	err := db.NewSelect().
		TableExpr("friends_of_php").
		Column("id", "advisory_id").
		Where("advisory_id IN (?)", bun.In(advisoryIds)).
		Scan(ctx, &results)

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve FriendsOfPHP UUIDs: %w", err)
	}

	result := make(map[string]uuid.UUID, len(results))
	for _, r := range results {
		result[r.AdvisoryId] = r.Id
	}

	return result, nil
}
