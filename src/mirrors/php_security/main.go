// Package php_security mirrors the FriendsOfPHP security advisories repository into the knowledge database.
package php_security

import (
	"fmt"
	"net/http"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/override"
	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/uptrace/bun"
)

// repositoryURL is a gzipped tarball of the advisory repository's default branch.
var repositoryURL = "https://codeload.github.com/FriendsOfPHP/security-advisories/tar.gz/refs/heads/master"

var logger = sourcesync.NewLogger()

// client bounds a stalled download so the run fails instead of hanging.
var client = &http.Client{Timeout: 10 * time.Minute}

// Update replaces the stored FriendsOfPHP advisories with the current repository content.
func Update(db *bun.DB) error {
	return sourcesync.RunCounted(db, knowledge.SourceFriendsOfPHP, func() (sourcesync.Result, error) {
		syncedAt := time.Now()
		snapshot, err := download()
		if err != nil {
			return sourcesync.Result{}, err
		}
		logger.WithFields(logrus.Fields{"source": knowledge.SourceFriendsOfPHP, "advisories": len(snapshot.advisories), "commit": snapshot.commit}).
			Info("Downloaded FriendsOfPHP repository")
		if err := store(db, snapshot.advisories, syncedAt); err != nil {
			return sourcesync.Result{}, err
		}
		// Each advisory file in the repository is one stored record.
		return sourcesync.Result{Watermark: syncedAt, UpstreamTotal: sourcesync.Total(len(snapshot.advisories))}, nil
	})
}

// download fetches and parses the whole advisory repository.
func download() (repositorySnapshot, error) {
	resp, err := client.Get(repositoryURL)
	if err != nil {
		return repositorySnapshot{}, fmt.Errorf("download FriendsOfPHP repository: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return repositorySnapshot{}, fmt.Errorf("download FriendsOfPHP repository: HTTP %d", resp.StatusCode)
	}
	return parseRepository(resp.Body)
}

// store upserts the snapshot's advisories, makes their package links match it, and retires advisories it lacks.
func store(db *bun.DB, advisories []knowledge.FriendsOfPHPAdvisory, syncedAt time.Time) error {
	ids := make([]string, len(advisories))
	for i, advisory := range advisories {
		ids[i] = advisory.AdvisoryId
	}
	if err := pgsql.AdoptPackagistFriendsOfPHP(db, ids); err != nil {
		return err
	}
	for start := 0; start < len(advisories); start += upsertChunkSize {
		if err := pgsql.BatchUpdateFriendsOfPHP(db, advisories[start:min(start+upsertChunkSize, len(advisories))]); err != nil {
			return err
		}
	}

	uuids, err := pgsql.GetFriendsOfPHPUUIDsByAdvisoryIds(db, ids)
	if err != nil {
		return fmt.Errorf("read FriendsOfPHP ids: %w", err)
	}
	stored := make([]uuid.UUID, 0, len(uuids))
	links := make([]knowledge.PackageVulnerability, 0, len(advisories))
	for _, advisory := range advisories {
		id, ok := uuids[advisory.AdvisoryId]
		if !ok {
			return fmt.Errorf("FriendsOfPHP advisory %s was not stored", advisory.AdvisoryId)
		}
		stored = append(stored, id)
		links = append(links, knowledge.PackageVulnerability{
			PackageName:      advisory.Composer,
			PackageEcosystem: "packagist",
			FriendsOfPhpId:   &id,
		})
	}
	if err := pgsql.ReplaceFriendsOfPHPPackageLinks(db, stored, links); err != nil {
		return fmt.Errorf("replace FriendsOfPHP package links: %w", err)
	}
	if err := pgsql.RetirePackagistFriendsOfPHP(db, syncedAt); err != nil {
		return err
	}
	return pgsql.ReconcileFriendsOfPHP(db, ids, syncedAt)
}

// upsertChunkSize bounds the advisories in one insert statement.
const upsertChunkSize = 500

// UseUpstream points the mirror at another repository tarball URL and returns a function that undoes it.
func UseUpstream(url string) (restore func()) {
	return override.Set(&repositoryURL, url)
}
