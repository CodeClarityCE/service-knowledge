package pgsql

import (
	"context"
	"log"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

func UpdateNvd(db *bun.DB, nvd []knowledge.NVDItem) {
	for _, vuln := range nvd {
		ctx := context.Background()
		exists, err := db.NewSelect().Model(&vuln).Where("nvd_id = ?", vuln.NVDId).Exists(ctx)
		if err != nil {
			log.Println(err)
		}

		if !exists {
			_, err = db.NewInsert().Model(&vuln).Exec(context.Background())
			if err != nil {
				log.Println(err)
			}
		}

		_, err = db.NewUpdate().Model(&vuln).WherePK().Exec(context.Background())
		if err != nil {
			log.Println(err)
		}
	}
}
