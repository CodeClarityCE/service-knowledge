package knowledge

import (
	"os"
	"testing"
)

func TestParsePairs(t *testing.T) {
	os.Setenv("NPM_URL", "https://replicate.npmjs.com/")
	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")
	Update()
}
