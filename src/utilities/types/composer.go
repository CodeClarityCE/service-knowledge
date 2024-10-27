package types

import "strings"

type Composer struct {
	Minified string                       `json:"minified"`
	Packages map[string][]ComposerPackage `json:"packages"`
}

type ComposerPackage struct {
	Name              string            `json:"name"`
	Description       string            `json:"description"`
	Homepage          string            `json:"homepage"`
	Version           string            `json:"version"`
	VersionNormalized string            `json:"version_normalized"`
	Authors           []Author          `json:"authors"`
	Time              string            `json:"time"`
	Keywords          []string          `json:"keywords"`
	Source            ComposerSource    `json:"source"`
	Dist              ComposerSource    `json:"dist"`
	License           []string          `json:"license"`
	Require           map[string]string `json:"require"`
	RequireDev        map[string]string `json:"require-dev"`
}

type ComposerSource struct {
	Url  string `json:"url"`
	Type string `json:"type"`
}

func ConvertComposerVersion(composerPackage []ComposerPackage, key string) []Version {
	var versions []Version
	for i := 0; i < len(composerPackage); i++ {
		var version Version
		version.Version = composerPackage[i].Version
		version.Time = composerPackage[i].Time
		version.Key = strings.ReplaceAll(key, "/", ":") + ":" + composerPackage[i].Version
		version.Dependencies = composerPackage[i].Require
		version.DevDependencies = composerPackage[i].RequireDev
		version.Extra = map[string]any{
			"Authors":            composerPackage[i].Authors,
			"Version_normalized": composerPackage[i].VersionNormalized,
			"Dist":               composerPackage[i].Dist,
		}
		versions = append(versions, version)
	}
	return versions
}

func ConvertComposerAuthor(authors []Author) []string {
	var authors_concatenated []string
	for _, author := range authors {
		authors_concatenated = append(authors_concatenated, author.Name+":"+author.Email)
	}
	return authors_concatenated
}
