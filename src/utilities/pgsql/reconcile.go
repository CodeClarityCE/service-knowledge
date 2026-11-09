package pgsql

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/uptrace/bun"
)

// ErrImplausibleRemoval means a snapshot would remove too many records to be trusted.
var ErrImplausibleRemoval = errors.New("snapshot would remove an implausible number of records")

const (
	// reconcileChunkSize bounds the ids in one statement.
	reconcileChunkSize = 1000
	// A source may remove this many records in one run whatever its size, so small tables can reconcile.
	removalFloor = 10
	// defaultMaxRemovalPercent matches the row-count drop that fails knowledge validation.
	defaultMaxRemovalPercent = 5.0
	// maxRemovalEnv overrides the percentage, for an operator-reviewed first reconcile.
	maxRemovalEnv = "KNOWLEDGE_RECONCILE_MAX_REMOVAL_PERCENT"
)

func maxRemovalPercent() float64 {
	if value, err := strconv.ParseFloat(os.Getenv(maxRemovalEnv), 64); err == nil && value >= 0 {
		return value
	}
	return defaultMaxRemovalPercent
}

// absentKeys returns the stored keys that the snapshot does not contain.
func absentKeys(stored, snapshot []string) []string {
	present := make(map[string]struct{}, len(snapshot))
	for _, key := range snapshot {
		present[key] = struct{}{}
	}
	var absent []string
	for _, key := range stored {
		if _, found := present[key]; !found {
			absent = append(absent, key)
		}
	}
	return absent
}

// checkRemoval refuses an empty snapshot and any removal above the allowed share of stored records.
func checkRemoval(source string, stored, absent, snapshot int) error {
	if absent == 0 {
		return nil
	}
	allowed := max(float64(stored)*maxRemovalPercent()/100, removalFloor)
	if snapshot == 0 || float64(absent) > allowed {
		return fmt.Errorf("%s: %w: %d of %d stored records missing from a snapshot of %d (allowed %.0f, see %s)",
			source, ErrImplausibleRemoval, absent, stored, snapshot, allowed, maxRemovalEnv)
	}
	return nil
}

func eachChunk[T any](keys []T, apply func([]T) error) error {
	for start := 0; start < len(keys); start += reconcileChunkSize {
		if err := apply(keys[start:min(start+reconcileChunkSize, len(keys))]); err != nil {
			return err
		}
	}
	return nil
}

func logReconciled(source string, stored, removed int) {
	dateLogger.WithFields(logrus.Fields{"source": source, "stored": stored, "removed": removed}).Info("Reconciled knowledge source")
}

// osvScope selects the rows the OSV mirror maintains, including ecosystem variants such as Packagist:https://packages.drupal.org/8.
const osvScope = `EXISTS (
	SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(affected) = 'array' THEN affected ELSE '[]'::jsonb END) entry
	WHERE split_part(entry->'package'->>'ecosystem', ':', 1) IN (?)
)`

// ReconcileOsv retires active in-scope advisories that a complete snapshot no longer contains.
// Call it only after every ecosystem downloaded and stored without error.
func ReconcileOsv(db *bun.DB, snapshotIDs []string, ecosystems []string, retiredAt time.Time) error {
	return retireAbsent(db, knowledge.SourceOSV, "osv", "osv_id", "osv_id", osvScope, []any{bun.In(ecosystems)}, snapshotIDs, retiredAt)
}

// retireAndUnlink retires the rows of table matching where, setting retired_at from retiredAt, and drops their package links.
// args fill the placeholders of retiredAt and where, in that order.
func retireAndUnlink(ctx context.Context, db bun.IDB, table, linkColumn, reason, retiredAt, where string, args ...any) error {
	query := fmt.Sprintf(`
		WITH retired AS (
			UPDATE ? SET retired_reason = ?, retired_at = %s
			WHERE %s
			RETURNING id
		)
		DELETE FROM package_vulnerability WHERE ? IN (SELECT id FROM retired)`, retiredAt, where)
	all := append(append([]any{bun.Ident(table), reason}, args...), bun.Ident(linkColumn))
	_, err := db.ExecContext(ctx, query, all...)
	return err
}

// removeAbsent applies apply to the keys read by query that a snapshot lacks, unless the removal guard refuses.
func removeAbsent(db *bun.DB, source string, query *bun.RawQuery, snapshot []string, apply func(ctx context.Context, tx bun.Tx, chunk []string) error) error {
	ctx := context.Background()

	var stored []string
	if err := query.Scan(ctx, &stored); err != nil {
		return fmt.Errorf("read stored %s keys: %w", source, err)
	}

	absent := absentKeys(stored, snapshot)
	if err := checkRemoval(source, len(stored), len(absent), len(snapshot)); err != nil {
		return err
	}

	err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		return eachChunk(absent, func(chunk []string) error { return apply(ctx, tx, chunk) })
	})
	if err != nil {
		return fmt.Errorf("remove absent %s records: %w", source, err)
	}
	logReconciled(source, len(stored), len(absent))
	return nil
}

// retireAbsent retires active rows of table in scope that a complete snapshot no longer contains and drops their package links.
func retireAbsent(db *bun.DB, source, table, keyColumn, linkColumn, scope string, scopeArgs []any, snapshot []string, retiredAt time.Time) error {
	read := append([]any{bun.Ident(keyColumn), bun.Ident(table)}, scopeArgs...)
	query := db.NewRaw("SELECT ? FROM ? WHERE retired_reason IS NULL AND ("+scope+")", read...)
	return removeAbsent(db, source, query, snapshot, func(ctx context.Context, tx bun.Tx, chunk []string) error {
		return retireAndUnlink(ctx, tx, table, linkColumn, knowledge.RetiredRemoved, "?", "? IN (?) AND retired_reason IS NULL",
			retiredAt, bun.Ident(keyColumn), bun.In(chunk))
	})
}

// ReconcileNvd retires active CVEs that a complete NVD fetch no longer contains.
// snapshotIDs must hold every record the fetch returned, including rejected and deferred ones.
func ReconcileNvd(db *bun.DB, snapshotIDs []string, retiredAt time.Time) error {
	return retireAbsent(db, knowledge.SourceNVD, "nvd", "nvd_id", "nvd_id", "TRUE", nil, snapshotIDs, retiredAt)
}

// ReconcileGcve retires active records that a complete GCVE fetch no longer contains.
// snapshotIDs must hold every record the fetch returned, including rejected ones.
func ReconcileGcve(db *bun.DB, snapshotIDs []string, retiredAt time.Time) error {
	return retireAbsent(db, knowledge.SourceGCVE, "gcve", "gcve_id", "gcve_id", "TRUE", nil, snapshotIDs, retiredAt)
}

// ReconcileFriendsOfPHP retires active advisories that a complete repository snapshot no longer contains.
func ReconcileFriendsOfPHP(db *bun.DB, snapshotIDs []string, retiredAt time.Time) error {
	return retireAbsent(db, knowledge.SourceFriendsOfPHP, "friends_of_php", "advisory_id", "friendsofphp_id", "TRUE", nil, snapshotIDs, retiredAt)
}

// SyncOsvRetirement retires the given advisories that are withdrawn and reactivates those the source asserts again.
func SyncOsvRetirement(db *bun.DB, osvIDs []string) error {
	ctx := context.Background()
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		return eachChunk(osvIDs, func(chunk []string) error {
			err := retireAndUnlink(ctx, tx, "osv", "osv_id", knowledge.RetiredWithdrawn, "withdrawn",
				"osv_id IN (?) AND withdrawn IS NOT NULL AND (retired_reason IS DISTINCT FROM ? OR retired_at IS DISTINCT FROM withdrawn)",
				bun.In(chunk), knowledge.RetiredWithdrawn)
			if err != nil {
				return fmt.Errorf("retire withdrawn OSV advisories: %w", err)
			}
			_, err = tx.ExecContext(ctx, `
				UPDATE osv SET retired_reason = NULL, retired_at = NULL
				WHERE osv_id IN (?) AND withdrawn IS NULL AND retired_reason IS NOT NULL`, bun.In(chunk))
			if err != nil {
				return fmt.Errorf("reactivate OSV advisories: %w", err)
			}
			return nil
		})
	})
}

// retirementDate is the upstream date when it is valid, else the current time.
func retirementDate(upstream string) time.Time {
	if normalized, ok := NormalizeTimestamp(upstream); ok && normalized != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, normalized); err == nil {
			return parsed
		}
	}
	return time.Now().UTC()
}

// RetireRejectedNvd retires stored CVEs that NVD now rejects and removes their package links.
// Their content is kept as it was while active, and unknown CVEs are not stored.
func RetireRejectedNvd(db *bun.DB, rejected []knowledge.NVDItem) error {
	ctx := context.Background()
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		for _, item := range rejected {
			err := retireAndUnlink(ctx, tx, "nvd", "nvd_id", knowledge.RetiredRejected, "?", "nvd_id = ? AND retired_reason IS NULL",
				retirementDate(item.LastModified), item.NVDId)
			if err != nil {
				return fmt.Errorf("retire rejected CVE %s: %w", item.NVDId, err)
			}
		}
		return nil
	})
}

// RetireStoredRejectedNvd retires rows already stored with a rejected status.
func RetireStoredRejectedNvd(db *bun.DB) error {
	err := retireAndUnlink(context.Background(), db, "nvd", "nvd_id", knowledge.RetiredRejected,
		`COALESCE("lastModified", now())`, `"vulnStatus" = 'Rejected' AND retired_reason IS NULL`)
	if err != nil {
		return fmt.Errorf("retire stored rejected NVD rows: %w", err)
	}
	return nil
}

// RetireRejectedGcve retires stored records that GCVE now rejects and removes their package links.
func RetireRejectedGcve(db *bun.DB, rejected []knowledge.GCVEItem) error {
	ctx := context.Background()
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		for _, item := range rejected {
			err := retireAndUnlink(ctx, tx, "gcve", "gcve_id", knowledge.RetiredRejected, "?", "gcve_id = ? AND retired_reason IS NULL",
				retirementDate(item.DateUpdated), item.GCVEId)
			if err != nil {
				return fmt.Errorf("retire rejected GCVE %s: %w", item.GCVEId, err)
			}
		}
		return nil
	})
}

// RetireStoredRejectedGcve retires rows already stored with a rejected state.
func RetireStoredRejectedGcve(db *bun.DB) error {
	err := retireAndUnlink(context.Background(), db, "gcve", "gcve_id", knowledge.RetiredRejected,
		"COALESCE(date_updated, now())", "state = 'REJECTED' AND retired_reason IS NULL")
	if err != nil {
		return fmt.Errorf("retire stored rejected GCVE rows: %w", err)
	}
	return nil
}

// clearRetirement reactivates records the source asserts again.
func clearRetirement(ctx context.Context, tx bun.Tx, table, idColumn string, ids []string) error {
	return eachChunk(ids, func(chunk []string) error {
		_, err := tx.ExecContext(ctx,
			"UPDATE ? SET retired_reason = NULL, retired_at = NULL WHERE ? IN (?) AND retired_reason IS NOT NULL",
			bun.Ident(table), bun.Ident(idColumn), bun.In(chunk))
		return err
	})
}

// reconcileSnapshotTable deletes rows of a table without retirement columns that a complete snapshot no longer contains.
func reconcileSnapshotTable(db *bun.DB, source, table, keyColumn string, snapshot []string) error {
	query := db.NewRaw("SELECT ? FROM ?", bun.Ident(keyColumn), bun.Ident(table))
	return removeAbsent(db, source, query, snapshot, func(ctx context.Context, tx bun.Tx, chunk []string) error {
		_, err := tx.ExecContext(ctx, "DELETE FROM ? WHERE ? IN (?)", bun.Ident(table), bun.Ident(keyColumn), bun.In(chunk))
		return err
	})
}

// ReconcileEPSS deletes scores for CVEs that a complete EPSS file no longer contains.
func ReconcileEPSS(db *bun.DB, snapshotCVEs []string) error {
	return reconcileSnapshotTable(db, knowledge.SourceEPSS, "epss", "cve", snapshotCVEs)
}

// ReconcileCWE deletes weaknesses that a complete CWE list no longer contains.
func ReconcileCWE(db *bun.DB, snapshotIDs []string) error {
	return reconcileSnapshotTable(db, knowledge.SourceCWE, "cwe", "cwe_id", snapshotIDs)
}

// ReconcileLicenses deletes licenses that a complete SPDX list no longer contains.
func ReconcileLicenses(db *bun.DB, snapshotIDs []string) error {
	return reconcileSnapshotTable(db, knowledge.SourceLicenses, "licenses", "licenseId", snapshotIDs)
}

// replacePackageLinks swaps the links of the given advisories for links, in one transaction.
func replacePackageLinks(db *bun.DB, column string, advisoryIDs []uuid.UUID, links []knowledge.PackageVulnerability) error {
	if len(advisoryIDs) == 0 {
		return nil
	}
	ctx := context.Background()
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		err := eachChunk(advisoryIDs, func(chunk []uuid.UUID) error {
			_, err := tx.ExecContext(ctx, "DELETE FROM package_vulnerability WHERE ? IN (?)", bun.Ident(column), bun.In(chunk))
			if err != nil {
				return fmt.Errorf("delete package links: %w", err)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if len(links) == 0 {
			return nil
		}
		_, err = tx.NewInsert().
			Model(&links).
			On(fmt.Sprintf("CONFLICT (package_name, package_ecosystem, %s) WHERE %s IS NOT NULL DO NOTHING", column, column)).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("insert %d package links: %w", len(links), err)
		}
		return nil
	})
}

// ReplaceOsvPackageLinks makes links the only package links of the given OSV advisories.
func ReplaceOsvPackageLinks(db *bun.DB, advisoryIDs []uuid.UUID, links []knowledge.PackageVulnerability) error {
	return replacePackageLinks(db, "osv_id", advisoryIDs, deduplicateOsvPackageVulnerabilities(links))
}

// ReplaceNvdPackageLinks makes links the only package links of the given NVD records.
func ReplaceNvdPackageLinks(db *bun.DB, advisoryIDs []uuid.UUID, links []knowledge.PackageVulnerability) error {
	return replacePackageLinks(db, "nvd_id", advisoryIDs, deduplicateNvdPackageVulnerabilities(links))
}

// ReplaceGcvePackageLinks makes links the only package links of the given GCVE records.
func ReplaceGcvePackageLinks(db *bun.DB, advisoryIDs []uuid.UUID, links []knowledge.PackageVulnerability) error {
	return replacePackageLinks(db, "gcve_id", advisoryIDs, deduplicateGcvePackageVulnerabilities(links))
}

// ReplaceFriendsOfPHPPackageLinks makes links the only package links of the given FriendsOfPHP advisories.
func ReplaceFriendsOfPHPPackageLinks(db *bun.DB, advisoryIDs []uuid.UUID, links []knowledge.PackageVulnerability) error {
	return replacePackageLinks(db, "friendsofphp_id", advisoryIDs, deduplicateFriendsOfPHPPackageVulnerabilities(links))
}
