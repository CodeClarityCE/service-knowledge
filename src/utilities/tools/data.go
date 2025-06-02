package tools

import (
	"github.com/CodeClarityCE/service-knowledge/src/utilities/types"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
)

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
