package knowledge

import (
	"fmt"

	"github.com/CodeClarityCE/service-knowledge/src/datedrestore"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/gcve"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/nvd"
	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
	"github.com/CodeClarityCE/service-knowledge/src/validation"
	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// refetchSource names a source and the sync that fetches all of it once its watermark is gone.
type refetchSource struct {
	source string
	sync   func() error
}

// FullRefetch clears the NVD and GCVE watermarks, then fetches each source completely and reconciles it.
// A source that fails keeps no watermark, so the next update repeats its full fetch.
func FullRefetch(db *bun.DB, configDB *bun.DB) error {
	return fullRefetch(db, []refetchSource{
		{knowledge_db.SourceNVD, func() error { return nvd.Update(db, configDB) }},
		{knowledge_db.SourceGCVE, func() error { return gcve.Update(db, configDB) }},
	})
}

// fullRefetch refuses a dated restore before touching any watermark.
func fullRefetch(db *bun.DB, sources []refetchSource) error {
	if err := datedrestore.RefuseMarked(db); err != nil {
		return err
	}
	return refetchSources(db, sources)
}

func refetchSources(db *bun.DB, sources []refetchSource) error {
	steps := make([]func() error, 0, len(sources))
	for _, source := range sources {
		steps = append(steps, func() error {
			if err := sourcesync.ResetWatermark(db, source.source); err != nil {
				return fmt.Errorf("%s: %w", source.source, err)
			}
			if err := source.sync(); err != nil {
				return err
			}
			// A completed re-fetch is a reviewed reset, so the next validation sets a new floor.
			return validation.ResetRowFloors(db, source.source)
		})
	}
	return runAll(steps)
}
