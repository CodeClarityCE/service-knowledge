package php_security

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

var previous = time.Now().Add(-48 * time.Hour).Truncate(time.Second)

// Advisory files as they appear in github.com/FriendsOfPHP/security-advisories.
const symfonyAdvisory = `title:     Routes behind a firewall are accessible even when not logged in
link:      https://symfony.com/blog/security-release-symfony-2-0-20-and-2-1-5-released
cve:       CVE-2012-6431
branches:
    2.0.x:
        time:     2012-03-19 15:59:52
        versions: ['>=2.0.0', '<2.0.19']
    2.1.x:
        time:     2012-12-20 10:00:00
        versions: ['>=2.1.0', '<2.1.5']
reference: composer://symfony/http-foundation
`

const twigAdvisory = `title:     "Sandbox bypass"
link:      https://github.com/twigphp/Twig/security/advisories/GHSA-0000-0000-0000
cve:       ~
branches:
    3.x:
        time:     ~
        versions: ['>=3.0.0', '<3.14.0']
reference: composer://twig/twig
`

// repository serves an archive of the advisory repository, as GitHub's tarball download does.
type repository struct {
	files map[string]string
}

func newRepository() *repository {
	return &repository{files: map[string]string{
		"README.md":                "# PHP Security Advisories Database",
		"composer.json":            "{}",
		".github/workflows/ci.yml": "on: push",
		"symfony/http-foundation/CVE-2012-6431.yaml": symfonyAdvisory,
		"twig/twig/2024-01-01.yaml":                  twigAdvisory,
	}}
}

func (r *repository) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(gz)
	for name, content := range r.files {
		header := &tar.Header{Name: "security-advisories-master/" + name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := archive.WriteHeader(header); err != nil {
			panic(err)
		}
		if _, err := archive.Write([]byte(content)); err != nil {
			panic(err)
		}
	}
	archive.Close()
	gz.Close()
	w.Header().Set("Content-Type", "application/x-gzip")
	_, _ = w.Write(buffer.Bytes())
}

func setup(t *testing.T, handler http.Handler) *bun.DB {
	t.Helper()
	db := testhelper.SetupSyncTestDB(t)
	testhelper.CreateFriendsOfPHPTable(t, db)
	testhelper.CreateTables(t, db, (*knowledge.PackageVulnerability)(nil))
	testhelper.CreatePackageLinkIndexes(t, db)
	testhelper.SeedWatermark(t, db, knowledge.SourceFriendsOfPHP, previous)

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	original := repositoryURL
	repositoryURL = server.URL + "/archive.tar.gz"
	t.Cleanup(func() { repositoryURL = original })
	return db
}

func readAdvisory(t *testing.T, db *bun.DB, advisoryID string) knowledge.FriendsOfPHPAdvisory {
	t.Helper()
	var advisory knowledge.FriendsOfPHPAdvisory
	if err := db.NewSelect().Model(&advisory).Where("advisory_id = ?", advisoryID).Scan(context.Background()); err != nil {
		t.Fatalf("read %s: %v", advisoryID, err)
	}
	return advisory
}

// linkedPackages lists the packages linked to each advisory, by advisory ID.
func linkedPackages(t *testing.T, db *bun.DB) map[string][]string {
	t.Helper()
	var rows []struct {
		AdvisoryID  string `bun:"advisory_id"`
		PackageName string `bun:"package_name"`
		Ecosystem   string `bun:"package_ecosystem"`
	}
	err := db.NewRaw(`SELECT f.advisory_id, p.package_name, p.package_ecosystem
		FROM package_vulnerability p JOIN friends_of_php f ON f.id = p.friendsofphp_id`).Scan(context.Background(), &rows)
	if err != nil {
		t.Fatalf("read package links: %v", err)
	}
	links := map[string][]string{}
	for _, row := range rows {
		links[row.AdvisoryID] = append(links[row.AdvisoryID], row.Ecosystem+":"+row.PackageName)
	}
	for _, packages := range links {
		sort.Strings(packages)
	}
	return links
}

func TestIngestsEveryAdvisoryInTheRepository(t *testing.T) {
	db := setup(t, newRepository())

	if err := Update(db); err != nil {
		t.Fatal(err)
	}

	symfony := readAdvisory(t, db, "symfony/http-foundation/CVE-2012-6431")
	if symfony.Composer != "symfony/http-foundation" || symfony.CVE != "CVE-2012-6431" ||
		symfony.Title != "Routes behind a firewall are accessible even when not logged in" ||
		symfony.Link != "https://symfony.com/blog/security-release-symfony-2-0-20-and-2-1-5-released" {
		t.Errorf("symfony advisory = %+v", symfony)
	}
	if got := symfony.Branches["2.1.x"].Versions; len(got) != 2 || got[0] != ">=2.1.0" || got[1] != "<2.1.5" {
		t.Errorf("2.1.x versions = %v", got)
	}
	if symfony.Published != "2012-03-19T15:59:52Z" {
		t.Errorf("published = %q, want the earliest branch time", symfony.Published)
	}

	twig := readAdvisory(t, db, "twig/twig/2024-01-01")
	if twig.CVE != "" || twig.Published != "" || twig.Composer != "twig/twig" {
		t.Errorf("twig advisory = %+v, want no CVE and no published date", twig)
	}

	want := map[string][]string{
		"symfony/http-foundation/CVE-2012-6431": {"packagist:symfony/http-foundation"},
		"twig/twig/2024-01-01":                  {"packagist:twig/twig"},
	}
	if got := linkedPackages(t, db); !equalLinks(got, want) {
		t.Errorf("package links = %v, want %v", got, want)
	}
	testhelper.AssertSucceededAfter(t, db, knowledge.SourceFriendsOfPHP, previous)
}

func equalLinks(got, want map[string][]string) bool {
	if len(got) != len(want) {
		return false
	}
	for id, packages := range want {
		if len(got[id]) != len(packages) {
			return false
		}
		for i := range packages {
			if got[id][i] != packages[i] {
				return false
			}
		}
	}
	return true
}

func TestFailedDownloadLeavesWatermark(t *testing.T) {
	db := setup(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))

	if err := Update(db); err == nil {
		t.Fatal("a failed download should fail the source")
	}
	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceFriendsOfPHP, previous)
}

func TestMalformedAdvisoryFailsTheSourceAndStoresNothing(t *testing.T) {
	repo := newRepository()
	repo.files["broken/pkg/2024-01-01.yaml"] = "title: [unterminated"
	db := setup(t, repo)

	if err := Update(db); err == nil {
		t.Fatal("a malformed advisory should fail the source")
	}
	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceFriendsOfPHP, previous)
	if count, _ := db.NewSelect().Table("friends_of_php").Count(context.Background()); count != 0 {
		t.Errorf("stored %d advisories from an incomplete snapshot, want 0", count)
	}
}

func TestPackageLinkFailureLeavesWatermark(t *testing.T) {
	db := setup(t, newRepository())
	testhelper.DropTable(t, db, "package_vulnerability")

	if err := Update(db); err == nil {
		t.Fatal("a failed package link insert should fail the source")
	}
	testhelper.AssertFailedWithWatermark(t, db, knowledge.SourceFriendsOfPHP, previous)
}

func TestAdvisoryRemovedFromTheRepositoryIsRetiredAndUnlinked(t *testing.T) {
	repo := newRepository()
	db := setup(t, repo)
	if err := Update(db); err != nil {
		t.Fatal(err)
	}

	delete(repo.files, "twig/twig/2024-01-01.yaml")
	if err := Update(db); err != nil {
		t.Fatal(err)
	}

	twig := readAdvisory(t, db, "twig/twig/2024-01-01")
	if twig.RetiredReason != knowledge.RetiredRemoved || twig.RetiredAt.IsZero() {
		t.Errorf("retirement = %+v, want removed with a date", twig.Retirement)
	}
	if links := linkedPackages(t, db); len(links["twig/twig/2024-01-01"]) != 0 || len(links["symfony/http-foundation/CVE-2012-6431"]) != 1 {
		t.Errorf("package links = %v, want only the symfony link", links)
	}

	repo.files["twig/twig/2024-01-01.yaml"] = twigAdvisory
	if err := Update(db); err != nil {
		t.Fatal(err)
	}
	if twig := readAdvisory(t, db, "twig/twig/2024-01-01"); twig.RetiredReason != "" {
		t.Errorf("retirement = %+v, want active once the repository has it again", twig.Retirement)
	}
	if links := linkedPackages(t, db); len(links["twig/twig/2024-01-01"]) != 1 {
		t.Errorf("package links = %v, want the twig link back", links)
	}
}

// seedPackagistRow stores an advisory as the former Packagist API importer wrote it, with its package link.
func seedPackagistRow(t *testing.T, db *bun.DB, advisoryID, remoteID, packageName string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	row := knowledge.FriendsOfPHPAdvisory{AdvisoryId: advisoryID, Title: "old", Reference: remoteID, Composer: packageName,
		Branches: map[string]knowledge.AdvisoryBranch{"affected": {Versions: []string{"<1.0"}}}}
	if _, err := db.NewInsert().Model(&row).Returning("id").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	link := knowledge.PackageVulnerability{PackageName: packageName, PackageEcosystem: "packagist", FriendsOfPhpId: &row.Id}
	if _, err := db.NewInsert().Model(&link).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	return row.Id
}

func TestPackagistRowsBecomeRepositoryAdvisoriesOrAreRetired(t *testing.T) {
	db := setup(t, newRepository())
	adopted := seedPackagistRow(t, db, "PKSA-aaaa-bbbb-cccc", "symfony/http-foundation/CVE-2012-6431.yaml", "symfony/http-foundation")
	seedPackagistRow(t, db, "PKSA-dddd-eeee-ffff", "GHSA-1111-2222-3333", "laravel/framework")

	if err := Update(db); err != nil {
		t.Fatal(err)
	}

	symfony := readAdvisory(t, db, "symfony/http-foundation/CVE-2012-6431")
	if symfony.Id != adopted || symfony.RetiredReason != "" || symfony.CVE != "CVE-2012-6431" {
		t.Errorf("symfony advisory = %+v, want the Packagist row %s kept active with the repository content", symfony, adopted)
	}
	github := readAdvisory(t, db, "PKSA-dddd-eeee-ffff")
	if github.RetiredReason != knowledge.RetiredRemoved || github.RetiredAt.IsZero() {
		t.Errorf("retirement = %+v, want the GitHub-sourced Packagist row removed", github.Retirement)
	}

	want := map[string][]string{
		"symfony/http-foundation/CVE-2012-6431": {"packagist:symfony/http-foundation"},
		"twig/twig/2024-01-01":                  {"packagist:twig/twig"},
	}
	if got := linkedPackages(t, db); !equalLinks(got, want) {
		t.Errorf("package links = %v, want %v", got, want)
	}
	if count, _ := db.NewSelect().Table("friends_of_php").Count(context.Background()); count != 3 {
		t.Errorf("stored %d advisories, want 3 (nothing deleted)", count)
	}
}

func TestBranchTimesInEveryRepositoryFormatAreReadInUTC(t *testing.T) {
	repo := newRepository()
	repo.files["silverstripe/framework/SS-2015-013-1.yaml"] = `title: XSS in a form field
link: https://www.silverstripe.org/download/security-releases/ss-2015-013/
branches:
    3.1.x:
        time: 2015-05-29 12:53:14 +1200
        versions: ['>=3.1.0', '<3.1.13']
reference: composer://silverstripe/framework
`
	repo.files["zetacomponents/mail/CVE-2017-15806.yaml"] = `title: Remote code execution
link: https://ezplatform.com/security-advisories/ezsa-2017-004
cve: CVE-2017-15806
branches:
    master:
        time: 2017-11-1 19:02:00
        versions: ['<1.8.2']
reference: composer://zetacomponents/mail
`
	db := setup(t, repo)

	if err := Update(db); err != nil {
		t.Fatal(err)
	}
	if got := readAdvisory(t, db, "silverstripe/framework/SS-2015-013-1").Published; got != "2015-05-29T00:53:14Z" {
		t.Errorf("published = %q, want the branch time in UTC", got)
	}
	if got := readAdvisory(t, db, "zetacomponents/mail/CVE-2017-15806").Published; got != "2017-11-01T19:02:00Z" {
		t.Errorf("published = %q, want the unpadded branch time read", got)
	}
}
