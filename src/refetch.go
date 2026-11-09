package knowledge

import (
	"fmt"

	"github.com/CodeClarityCE/service-knowledge/src/mirrors/gcve"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/nvd"
	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
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
	return refetchSources(db, []refetchSource{
		{knowledge_db.SourceNVD, func() error { return nvd.Update(db, configDB) }},
		{knowledge_db.SourceGCVE, func() error { return gcve.Update(db, configDB) }},
	})
}

func refetchSources(db *bun.DB, sources []refetchSource) error {
	steps := make([]func() error, 0, len(sources))
	for _, source := range sources {
		steps = append(steps, func() error {
			if err := sourcesync.ResetWatermark(db, source.source); err != nil {
				return fmt.Errorf("%s: %w", source.source, err)
			}
			return source.sync()
		})
	}
	return runAll(steps)
}
