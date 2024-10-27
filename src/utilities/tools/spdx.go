package tools

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/CodeClarityCE/service-knowledge/src/utilities/types"
)

// spdx splits a given value by "OR" or "AND" and returns the resulting substrings as a slice of strings.
// If the value contains "OR", it removes any parentheses and splits the value by "OR".
// If the value contains "AND", it removes any parentheses and splits the value by "AND".
// If the value does not contain "OR" or "AND", it returns a slice containing the original value.
func spdx(value string) []string {
	// check if OR in value
	if strings.Contains(value, " OR ") {
		// Remove parenthesis
		value = strings.ReplaceAll(value, "(", "")
		value = strings.ReplaceAll(value, ")", "")

		// split value by OR
		split := strings.Split(value, " OR ")

		return split
	} else if strings.Contains(value, " AND ") {
		// Remove parenthesis
		value = strings.ReplaceAll(value, "(", "")
		value = strings.ReplaceAll(value, ")", "")

		// split value by OR
		split := strings.Split(value, " OR ")

		return split
	}

	return []string{value}
}

// parseLicense parses the license information from the given package and returns a slice of LinkLicensePackage.
// The package can be of any type, including string, map[string]any, or []any.
// If the package is nil, an empty slice is returned.
// If the license field is a string, it is split into multiple licenses using the spdx function.
// If the license field is an object, the "type" field is checked first, followed by "name", "license", "key", "value", and "prefered" fields.
// If the license field is an array, each element is processed recursively.
// If the license field is of type types.LicenseNpm, the "Type" field is used as the license key.
// If any problem occurs during the parsing process, an error message is logged and appended to a file.
func parseLicense(pack any, from string) []types.LinkLicensePackage {
	var links []types.LinkLicensePackage

	if pack == nil {
		return links
	}

	// If field license is string
	if stringPack, ok := pack.(string); ok {
		for _, license := range spdx(stringPack) {
			links = append(links, types.LinkLicensePackage{
				FromKey:    from,
				LicenseKey: license,
			})
		}
	} else if mapPackage, ok := pack.(map[string]any); ok { // If field license is object
		license := mapPackage["type"]
		if license == nil {
			// map[name:MIT url:https://github.com/nico3333fr/van11y-accessible-modal-window-aria/blob/master/LICENSE]
			license = mapPackage["name"]
			if license == nil {
				// map[license:GPL-3.0 url:https://www.gnu.org/licenses/gpl-3.0.html]
				license = mapPackage["license"]
				if license == nil {
					// map[key:GNU General Public License value:3]
					license = fmt.Sprintf("%s %s", mapPackage["key"], mapPackage["value"])
					if license == " " {
						// map[prefered:MIT]
						license = mapPackage["prefered"]
					}
				}
			}
		}
		if stringLicense, ok := license.(string); ok {
			links = append(links, types.LinkLicensePackage{
				FromKey:    from,
				LicenseKey: stringLicense,
			})
		} else {
			log.Println("1 Problem with license", pack, license)
			appendToFile(fmt.Sprintf("1 %v ::: %s\n", pack, from))
		}
	} else if arrayPackage, ok := pack.([]any); ok { // If field license is array
		for _, license := range arrayPackage {
			if stringLicense, ok := license.(string); ok { // If field license is string
				for _, lic := range spdx(stringLicense) {
					links = append(links, types.LinkLicensePackage{
						FromKey:    from,
						LicenseKey: lic,
					})
				}
			} else if _, ok := license.(map[string]any); ok { // If field license is object
				lic := license.(map[string]any)["type"]
				if lic == nil {
					// map[name:MIT url:
					lic = license.(map[string]any)["name"]
					if lic == nil {
						// map[license:GPL-3.0 url:https://www.gnu.org/licenses/gpl-3.0.html]
						lic = license.(map[string]any)["license"]
						if lic == nil {
							// map[key:GNU General Public License value:3]
							lic = fmt.Sprintf("%s %s", license.(map[string]any)["key"], license.(map[string]any)["value"])
							if lic == " " {
								// map[prefered:MIT]
								lic = license.(map[string]any)["prefered"]
							}
						}
					}
				}

				if stringLic, ok := lic.(string); ok {
					links = append(links, types.LinkLicensePackage{
						FromKey:    from,
						LicenseKey: stringLic,
					})
				} else {
					log.Println("2 Problem with license", pack, license)
					appendToFile(fmt.Sprintf("2 %v ::: %s\n", pack, from))
				}
			} else if licenseNpmPack, ok := pack.(types.LicenseNpm); ok { // If field license is object
				links = append(links, types.LinkLicensePackage{
					FromKey:    from,
					LicenseKey: licenseNpmPack.Type,
				})
			} else {
				log.Println("3 Problem with license", pack, license)
				appendToFile(fmt.Sprintf("3 %v ::: %s\n", pack, from))
			}
		}
	} else {
		log.Println("4 Problem with license", pack)
		appendToFile(fmt.Sprintf("4 %v ::: %s\n", pack, from))
	}
	return links
}

// CleanLicense cleans the given license and returns a list of cleaned licenses.
// The function takes an input license of any type and a slice of licenses of type types.LicenseNpm.
// It returns a slice of strings representing the cleaned licenses.
func CleanLicense(license any, licenses []types.LicenseNpm) []string {
	return []string{""}
}

// appendToFile appends the given text to the "licenses.txt" file.
// If the file does not exist, it will be created.
// If an error occurs while opening or writing to the file, it will be logged.
func appendToFile(text string) {
	filename := "licenses.txt"
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		log.Println(err)
	}
}
