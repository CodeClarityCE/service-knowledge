package types

import (
	"strings"

	semver "github.com/CodeClarityCE/utility-node-semver"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
)

type Npm struct {
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Revision    string                `json:"_rev"`
	Homepage    string                `json:"homepage"`
	Versions    map[string]NpmVersion `json:"versions"`
	Time        any                   `json:"time"`
	Repository  any                   `json:"repository"`
	Keywords    any                   `json:"keywords"`
	DistTags    map[string]string     `json:"dist-tags"`
	Maintainers []Maintainers         `json:"maintainers"`
	Author      any                   `json:"author"`
	License     any                   `json:"license"`
	Licenses    []LicenseNpm          `json:"licenses"`
}

type NpmVersion struct {
	Version              string            `json:"version"`
	Author               interface{}       `json:"author"`
	Engines              any               `json:"engines"`
	Dist                 Dist              `json:"dist"`
	License              any               `json:"license"`
	Licenses             any               `json:"licenses"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     any               `json:"peerDependencies"`
	PeerDependenciesMeta any               `json:"peerDependenciesMeta"`
	BundleDependencies   any               `json:"bundleDependencies"`
	BundledDependencies  any               `json:"bundledDependencies"`
	OptionalDependencies any               `json:"optionalDependencies"`
	Deprecated           interface{}       `json:"deprecated"`
}

type LicenseNpm struct {
	Type string `json:"type"`
	Url  string `json:"url"`
}

type Repository struct {
	Type      string `json:"type"`
	Url       string `json:"url"`
	Directory string `json:"directory"`
}

type Dist struct {
	Shasum     string      `json:"shasum"`
	Tarball    string      `json:"tarball"`
	Integrity  string      `json:"integrity"`
	Signatures []Signature `json:"signatures"`
}

type Signature struct {
	Keyid string
	Sig   string
}

type Maintainers struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type Author struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func GetLatestVersion(npmVersions map[string]NpmVersion) string {
	versions := []string{}

	for key := range npmVersions {
		versions = append(versions, npmVersions[key].Version)
		// if latestVersion == "" || npmVersions[key].Version > latestVersion {
		// 	latestVersion = npmVersions[key].Version
		// }
	}

	versions, err := semver.SortStrings(-1, versions)
	if err != nil {
		return ""
	}
	return versions[0]
}

func ConvertNpmVersion(npm Npm) []knowledge.Version {
	var versions []knowledge.Version

	for key := range npm.Versions {
		var version knowledge.Version
		version.Version = npm.Versions[key].Version

		version.Dependencies = npm.Versions[key].Dependencies
		version.DevDependencies = npm.Versions[key].DevDependencies

		var author string
		author_value, ok := npm.Author.(Author)
		if ok {
			author = author_value.Name
		} else {
			author_value, ok := npm.Author.(string)
			if ok {
				author = author_value
			}
		}

		version.Extra = map[string]any{
			"Engines":              npm.Versions[key].Engines,
			"Author":               author,
			"Dist":                 npm.Versions[key].Dist,
			"PeerDependencies":     npm.Versions[key].PeerDependencies,
			"BundleDependencies":   npm.Versions[key].BundleDependencies,
			"BundledDependencies":  npm.Versions[key].BundledDependencies,
			"PeerDependenciesMeta": npm.Versions[key].PeerDependenciesMeta,
			"OptionalDependencies": npm.Versions[key].OptionalDependencies,
			"Deprecated":           npm.Versions[key].Deprecated,
		}
		versions = append(versions, version)
	}
	return versions
}

func CleanName(value string) string {
	name := strings.ReplaceAll(value, "/", ":")
	name = strings.ReplaceAll(name, "~", ":")
	return name
}

// func ConvertNpmMaintainers(maintainers []Maintainers) []string {
// 	var maintainers_concatenated []string
// 	for _, maintainer := range maintainers {
// 		maintainers_concatenated = append(maintainers_concatenated, maintainer.Name+":"+maintainer.Email)
// 	}
// 	return maintainers_concatenated
// }

// func ConvertNpmDistTags(dist map[string]string) []string {
// 	var dist_tags []string

// 	for key, value := range dist {
// 		dist_tags = append(dist_tags, key+":"+value)
// 	}
// 	return dist_tags
// }

// func ConvertNpmEngines(engines map[string]string) []string {
// 	var engines_concatenated []string

// 	for key, value := range engines {
// 		engines_concatenated = append(engines_concatenated, key+":"+value)
// 	}
// 	return engines_concatenated
// }
