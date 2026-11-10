package php_security

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"go.yaml.in/yaml/v3"
)

// repositorySnapshot is every advisory in one download of the repository.
type repositorySnapshot struct {
	advisories []knowledge.FriendsOfPHPAdvisory
	// commit is the archived commit, when the archive names it.
	commit string
}

// advisoryFile is the YAML layout of one advisory file.
type advisoryFile struct {
	Title     string                `yaml:"title"`
	Link      string                `yaml:"link"`
	CVE       string                `yaml:"cve"`
	Reference string                `yaml:"reference"`
	Branches  map[string]branchFile `yaml:"branches"`
}

type branchFile struct {
	Time     string   `yaml:"time"`
	Versions []string `yaml:"versions"`
}

// branchTimeLayouts are how advisory files write branch times. Times without an offset are UTC.
var branchTimeLayouts = []string{"2006-1-2 15:04:05", "2006-1-2 15:04:05 -0700"}

func parseBranchTime(raw string) (time.Time, error) {
	var err error
	for _, layout := range branchTimeLayouts {
		var at time.Time
		if at, err = time.Parse(layout, raw); err == nil {
			return at, nil
		}
	}
	return time.Time{}, err
}

// parseRepository reads every advisory from a gzipped tarball of the repository.
// Advisories live at <vendor>/<package>/<name>.yaml below the archive's top directory.
func parseRepository(r io.Reader) (repositorySnapshot, error) {
	var snapshot repositorySnapshot
	gz, err := gzip.NewReader(r)
	if err != nil {
		return snapshot, fmt.Errorf("read FriendsOfPHP archive: %w", err)
	}
	archive := tar.NewReader(gz)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return snapshot, fmt.Errorf("read FriendsOfPHP archive: %w", err)
		}
		if header.Typeflag == tar.TypeXGlobalHeader {
			snapshot.commit = header.PAXRecords["comment"]
			continue
		}
		id, ok := advisoryID(header)
		if !ok {
			continue
		}
		content, err := io.ReadAll(archive)
		if err != nil {
			return snapshot, fmt.Errorf("read FriendsOfPHP advisory %s: %w", id, err)
		}
		advisory, err := parseAdvisory(id, content)
		if err != nil {
			return snapshot, err
		}
		snapshot.advisories = append(snapshot.advisories, advisory)
	}
	if len(snapshot.advisories) == 0 {
		return snapshot, fmt.Errorf("FriendsOfPHP archive holds no advisories: %w", sourcesync.ErrNoUpstreamRecords)
	}
	return snapshot, nil
}

// advisoryID is the file's path without the top directory and extension, for advisory files only.
func advisoryID(header *tar.Header) (string, bool) {
	if header.Typeflag != tar.TypeReg {
		return "", false
	}
	parts := strings.Split(header.Name, "/")
	if len(parts) != 4 || path.Ext(parts[3]) != ".yaml" || strings.HasPrefix(parts[1], ".") {
		return "", false
	}
	return strings.TrimSuffix(strings.Join(parts[1:], "/"), ".yaml"), true
}

// parseAdvisory converts one advisory file. Its package comes from the reference, else from its path.
func parseAdvisory(id string, content []byte) (knowledge.FriendsOfPHPAdvisory, error) {
	var file advisoryFile
	if err := yaml.Unmarshal(content, &file); err != nil {
		return knowledge.FriendsOfPHPAdvisory{}, fmt.Errorf("parse FriendsOfPHP advisory %s: %w", id, err)
	}
	if file.Title == "" || len(file.Branches) == 0 {
		return knowledge.FriendsOfPHPAdvisory{}, fmt.Errorf("parse FriendsOfPHP advisory %s: missing title or branches", id)
	}

	packageName := strings.TrimPrefix(file.Reference, "composer://")
	if file.Reference == "" || packageName == file.Reference {
		packageName = path.Dir(id)
	}

	branches := make(map[string]knowledge.AdvisoryBranch, len(file.Branches))
	var earliest time.Time
	for name, branch := range file.Branches {
		branches[name] = knowledge.AdvisoryBranch{Versions: branch.Versions, Time: branch.Time}
		if branch.Time == "" {
			continue
		}
		at, err := parseBranchTime(branch.Time)
		if err != nil {
			return knowledge.FriendsOfPHPAdvisory{}, fmt.Errorf("parse FriendsOfPHP advisory %s: branch %s time: %w", id, name, err)
		}
		if earliest.IsZero() || at.Before(earliest) {
			earliest = at
		}
	}
	published := ""
	if !earliest.IsZero() {
		published = earliest.UTC().Format(time.RFC3339)
	}

	return knowledge.FriendsOfPHPAdvisory{
		AdvisoryId:  id,
		Title:       file.Title,
		CVE:         file.CVE,
		Link:        file.Link,
		Reference:   file.Reference,
		Composer:    packageName,
		Description: file.Title,
		Branches:    branches,
		Published:   published,
	}, nil
}
