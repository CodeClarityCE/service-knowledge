package validation

import (
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"testing"

	"github.com/CodeClarityCE/utility-boilerplates/testdeps"
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
		source, err := os.ReadFile(file) //nolint:gosec // G304: test reads the API's migration files
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
// Without either, as in this repo's own CI, the test fetches the API's migrations from GitHub.
func TestExpectedMigrationsMatchTheAPI(t *testing.T) {
	dir := os.Getenv("KNOWLEDGE_API_MIGRATIONS_DIR")
	if dir == "" {
		dir = filepath.Join("..", "..", "..", "..", "..", "api", "src", "migrations")
	}
	if _, err := os.Stat(filepath.Join(dir, "knowledge")); err != nil { //nolint:gosec // G703: test-only path override
		dir = fetchAPIMigrations(t)
	}

	if got := apiMigrations(t, dir, "knowledge"); !slices.Equal(got, ExpectedKnowledgeMigrations) {
		t.Errorf("API knowledge migrations = %v\nwant ExpectedKnowledgeMigrations to match", got)
	}
	if got := apiMigrations(t, dir, "config"); !slices.Equal(got, ExpectedConfigMigrations) {
		t.Errorf("API config migrations = %v\nwant ExpectedConfigMigrations to match", got)
	}
}

const apiRepo = "https://github.com/CodeClarityCE/api.git"

// fetchAPIMigrations clones the API's migrations folder, from the branch named like this one if the API has it, else develop.
func fetchAPIMigrations(t *testing.T) string {
	t.Helper()
	ref := "develop"
	for _, branch := range []string{os.Getenv("GITHUB_HEAD_REF"), os.Getenv("GITHUB_REF_NAME")} {
		if branch != "" && osexec.Command("git", "ls-remote", "--exit-code", "--heads", apiRepo, branch).Run() == nil { //nolint:gosec // G204: test-only git call on a CI branch name
			ref = branch
			break
		}
	}
	checkout := t.TempDir()
	for _, args := range [][]string{
		{"clone", "--quiet", "--depth", "1", "--filter=blob:none", "--sparse", "--branch", ref, apiRepo, checkout},
		{"-C", checkout, "sparse-checkout", "set", "src/migrations"},
	} {
		cmd := osexec.Command("git", args...) //nolint:gosec // G204: test-only git call; ref is develop or a branch ls-remote just found on the API repo
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			testdeps.Unavailable(t, "the API repository at "+apiRepo, fmt.Errorf("%w: %s", err, out))
		}
	}
	t.Logf("comparing with the API migrations on %s", ref)
	return filepath.Join(checkout, "src", "migrations")
}
