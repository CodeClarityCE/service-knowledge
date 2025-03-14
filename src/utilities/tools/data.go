package tools

import (
	"log"
	"strings"

	"github.com/CodeClarityCE/service-knowledge/src/utilities/types"
	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
)

// CreatePackageInfoComposer creates a package info composer based on the provided result.
// It iterates over the packages in the result and populates the package info with the first package's details.
// If a package has no name, it sets the package name to an empty string and uses the package key as the description.
// It returns the created package info.
func CreatePackageInfoComposer(result types.Composer) types.Package {
	var pack types.Package
	for key := range result.Packages {
		if len(result.Packages[key]) == 0 {
			pack.Name = ""
			pack.Description = key
			return pack
		}
		pack.Name = result.Packages[key][0].Name
		pack.Key = types.CleanName(result.Packages[key][0].Name)
		pack.Description = result.Packages[key][0].Description
		pack.Homepage = result.Packages[key][0].Homepage
		pack.Time = result.Packages[key][0].Time
		pack.Version = result.Packages[key][0].Version
		pack.Versions = types.ConvertComposerVersion(result.Packages[key], key)
		pack.Source.Type = result.Packages[key][0].Source.Type
		pack.Source.Url = result.Packages[key][0].Source.Url
		pack.Keywords = result.Packages[key][0].Keywords
	}
	return pack
}

// CreateExtraVersionInfoComposer creates a map of extra version information for a given Composer result.
// It iterates over the packages in the result and adds the package version, authors, version normalized, and distribution information to the map.
// The map is then returned as the result.
func CreateExtraVersionInfoComposer(result types.Composer) map[string]any {
	extra_version_info := make(map[string]any)
	for key := range result.Packages {
		for _, pack := range result.Packages[key] {
			extra_version_info[pack.Version] = map[string]any{
				"Authors":            pack.Authors,
				"Version_normalized": pack.VersionNormalized,
				"Dist":               pack.Dist.Type + ":" + pack.Dist.Url,
			}
		}
	}
	return extra_version_info
}

// CreateLinkNpm creates a list of LinkLicensePackage based on the provided Npm package information.
// It takes a parameter 'pack' of type types.Npm, which represents the Npm package.
// It returns a slice of LinkLicensePackage.
func CreateLinkNpm(pack types.Npm) []types.LinkLicensePackage {
	from := dbhelper.Config.Collection.JS + "/" + strings.ReplaceAll(pack.Name, "/", ":")
	links := parseLicense(pack.License, from)
	for _, license := range pack.Licenses {
		links = append(links, types.LinkLicensePackage{
			FromKey:    from,
			LicenseKey: license.Type,
		})
	}

	for _, version := range pack.Versions {
		from := dbhelper.Config.Collection.Versions + "/" + strings.ReplaceAll(pack.Name, "/", ":") + ":" + version.Version
		links = append(links, parseLicense(version.License, from)...)

		if licenses, ok := version.Licenses.([]knowledge.LicenseNpm); ok {
			for _, license := range licenses {
				links = append(links, types.LinkLicensePackage{
					FromKey:    from,
					LicenseKey: license.Type,
				})
			}
		} else {
			log.Println("Error: Unable to parse licenses for version", version.Licenses)
		}

	}

	return links
}

// CreateLinkMaven creates a list of LinkLicensePackage based on the provided Maven package.
// It takes a parameter of type types.Maven which represents the Maven package.
// It returns a slice of LinkLicensePackage.
func CreateLinkMaven(pack types.Maven) []types.LinkLicensePackage {
	from := dbhelper.Config.Collection.Java + "/" + strings.ReplaceAll(pack.Name, "/", ":")
	var links []types.LinkLicensePackage
	for _, license := range pack.Licenses {
		links = append(links, types.LinkLicensePackage{
			FromKey:    from,
			LicenseKey: license.Name,
		})
	}

	// for _, version := range pack.Versions {
	// 	from := dbhelper.Config.Collection.Versions + "/" + strings.ReplaceAll(pack.Name, "/", ":") + ":" + version.Version
	// 	links = append(links, parseLicense(version.License, from)...)

	// 	for _, license := range version.Licenses {
	// 		links = append(links, types.LinkLicensePackage{
	// 			FromKey:    from,
	// 			LicenseKey: license.Type,
	// 		})
	// 	}
	// }

	return links
}

// CreateLinkComposer creates a list of LinkLicensePackage objects based on the provided Composer object.
// It iterates over the packages in the Composer object and generates LinkLicensePackage objects for each package, version, and license combination.
// The generated LinkLicensePackage objects contain the necessary information to establish links between different entities in the system.
// The resulting list of LinkLicensePackage objects is returned.
func CreateLinkComposer(pack types.Composer) []types.LinkLicensePackage {
	var links []types.LinkLicensePackage

	for key := range pack.Packages {
		for _, version := range pack.Packages[key] {
			for _, license := range version.License {
				links = append(links, types.LinkLicensePackage{
					FromKey:    dbhelper.Config.Collection.Versions + "/" + strings.ReplaceAll(key, "/", ":") + ":" + version.Version,
					LicenseKey: license,
				})
			}
		}

	}
	return links
}

// CreatePackageInfoNpm creates a types.Package object based on the provided types.Npm object.
// It populates the fields of the package object with the corresponding values from the npm object.
// If the repository field in the npm object is a string, it sets the source type to "string" and the source URL to the repository value.
// If the repository field in the npm object is a map, it extracts the source type and source URL from the map and sets them in the package object.
// Finally, it calls CreateExtraPackageInfoNpm to populate the extra field of the package object.
func CreatePackageInfoNpm(result types.Npm) knowledge.Package {
	var pack knowledge.Package
	pack.Name = result.Name
	pack.Description = result.Description
	pack.Homepage = result.Homepage
	pack.LatestVersion = types.GetLatestVersion(result.Versions)
	pack.Versions = types.ConvertNpmVersion(result)
	pack.Time = result.Time[pack.LatestVersion]

	// Repository can be a string or a map
	if result.Repository != nil {
		if _, ok := result.Repository.(string); ok {
			pack.Source.Type = "string"
			pack.Source.Url = result.Repository.(string)
		} else if _, ok := result.Repository.(map[string]interface{}); ok {
			sourceType := result.Repository.(map[string]interface{})["type"]
			sourceUrl := result.Repository.(map[string]interface{})["url"]
			if sourceType != nil {
				pack.Source.Type = sourceType.(string)
			}
			if sourceUrl != nil {
				pack.Source.Url = sourceUrl.(string)
			}
		}
	}

	if license, ok := result.License.(knowledge.LicenseNpm); ok {
		pack.License = license.Type
	} else if license, ok := result.License.(string); ok {
		pack.License = license
	}

	if keywords, ok := result.Repository.([]string); ok {
		pack.Keywords = keywords
	}
	pack.Extra = CreateExtraPackageInfoNpm(result)
	return pack
}

// CreateExtraPackageInfoNpm creates a map containing extra package information for an Npm package.
// It takes a result of type types.Npm as input and returns a map[string]any.
// The map contains the following key-value pairs:
// - "Author": The name of the package author.
// - "Dist_tags": The distribution tags of the package.
// - "Maintainers": The maintainers of the package.
func CreateExtraPackageInfoNpm(result types.Npm) map[string]any {
	extra_package_info := make(map[string]any)

	var author string
	author_value, ok := result.Author.(types.Author)
	if ok {
		author = author_value.Name
	} else {
		author_value, ok := result.Author.(string)
		if ok {
			author = author_value
		}
	}
	extra_package_info["Author"] = author

	extra_package_info["Dist_tags"] = result.DistTags
	extra_package_info["Maintainers"] = result.Maintainers
	return extra_package_info
}

func CreatePackageInfoMaven(result types.Maven) types.Package {
	var pack types.Package
	pack.Name = result.Name
	// pack.Revision = result.Revision
	pack.Key = types.CleanName(pack.Name)
	pack.Description = result.Description
	pack.Homepage = result.Url
	// pack.Time = result.Time["modified"]
	pack.Version = result.Version

	var licenseNames []string
	for _, license := range result.Licenses {
		licenseNames = append(licenseNames, license.Name)
	}
	pack.Licenses = licenseNames

	pack.Source.Type = result.SCM.Connection
	pack.Source.Url = result.SCM.Url

	// pack.Keywords = result.Keywords
	// pack.Extra = CreateExtraPackageInfoNpm(result)
	return pack
}
