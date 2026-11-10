package validation

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"testing"
)

var migrationClass = regexp.MustCompile(`export class (\w+)`)

// apiMigrations lists the migration classes in one API migrations folder, oldest first.
func apiMigrations(t *testing.T, dir, folder string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, folder, "*.ts"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	var names []string
	for _, file := range files {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if match := migrationClass.FindSubmatch(source); match != nil {
			names = append(names, string(match[1]))
		}
	}
	return names
}

// The API checkout sits next to backend/ in the umbrella repo; KNOWLEDGE_API_MIGRATIONS_DIR overrides it.
func TestExpectedMigrationsMatchTheAPI(t *testing.T) {
	dir := os.Getenv("KNOWLEDGE_API_MIGRATIONS_DIR")
	if dir == "" {
		dir = filepath.Join("..", "..", "..", "..", "..", "api", "src", "migrations")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("no API migrations at %s", dir)
	}

	if got := apiMigrations(t, dir, "knowledge"); !slices.Equal(got, ExpectedKnowledgeMigrations) {
		t.Errorf("API knowledge migrations = %v\nwant ExpectedKnowledgeMigrations to match", got)
	}
	if got := apiMigrations(t, dir, "config"); !slices.Equal(got, ExpectedConfigMigrations) {
		t.Errorf("API config migrations = %v\nwant ExpectedConfigMigrations to match", got)
	}
}
