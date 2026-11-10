package knowledge

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CodeClarityCE/service-knowledge/src/mirrors/php_security"
	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledgedb "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// fullFriendsOfPHPRepository holds three advisories and files that are not advisories.
var fullFriendsOfPHPRepository = map[string]string{
	"README.md":     "# PHP Security Advisories Database",
	"composer.json": "{}",
	"symfony/http-foundation/CVE-2012-6431.yaml": friendsOfPHPAdvisory("Routes behind a firewall", "composer://symfony/http-foundation"),
	"symfony/http-kernel/CVE-2019-18887.yaml":    friendsOfPHPAdvisory("Fragment URI signature bypass", "composer://symfony/http-kernel"),
	"twig/twig/2024-01-01.yaml":                  friendsOfPHPAdvisory("Sandbox bypass", "composer://twig/twig"),
}

func friendsOfPHPAdvisory(title, reference string) string {
	return "title: " + title + "\nlink: https://example.com\ncve: ~\nbranches:\n    1.x:\n        time: 2024-01-01 10:00:00\n        versions: ['<1.2.0']\nreference: " + reference + "\n"
}

func init() {
	registerFakeSource(fakeSource{
		name: knowledgedb.SourceFriendsOfPHP,
		createTables: func(t *testing.T, db *bun.DB) {
			testhelper.CreateTables(t, db, (*knowledgedb.FriendsOfPHPAdvisory)(nil), (*knowledgedb.PackageVulnerability)(nil))
			testhelper.CreatePackageLinkIndexes(t, db)
			if _, err := db.Exec("CREATE UNIQUE INDEX ON friends_of_php (advisory_id)"); err != nil {
				t.Fatal(err)
			}
		},
		serve: func(t *testing.T, empty bool) {
			files := fullFriendsOfPHPRepository
			if empty {
				files = map[string]string{"README.md": "# PHP Security Advisories Database"}
			}
			archive := tarFriendsOfPHPRepository(t, files)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(archive)
			}))
			t.Cleanup(server.Close)
			t.Cleanup(php_security.UseUpstream(server.URL))
		},
		upstreamTotal: 3,
		breaks:        upstreamTotalBreaks(knowledgedb.SourceFriendsOfPHP),
	})
}

// tarFriendsOfPHPRepository builds a gzipped tarball of the advisory repository, as GitHub serves it.
func tarFriendsOfPHPRepository(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	archive := tar.NewWriter(gz)
	for name, content := range files {
		header := &tar.Header{Name: "security-advisories-master/" + name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
