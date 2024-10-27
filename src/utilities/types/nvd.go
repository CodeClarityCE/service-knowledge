// Description: This file contains the NVD struct and all the functions that are used to parse the NVD data
package types

// Import all the packages that are needed
import "strings"

// NVD struct
// This struct contains all the fields that are needed to parse the NVD data
// The fields are based on the NVD JSON schema
// https://nvd.nist.gov/vuln/data-feeds#JSON_FEED
type NVD struct {
	Vulnerabilities []map[string]CVE `json:"vulnerabilities"`
}

type CVE struct {
	Key              string        `json:"_key,omitempty"`
	Id               string        `json:"id"`
	SourceIdentifier string        `json:"sourceIdentifier"`
	Published        string        `json:"published"`
	LastModified     string        `json:"lastModified"`
	VulnStatus       string        `json:"vulnStatus"`
	Descriptions     []Description `json:"descriptions"`
	Metrics          any           `json:"metrics"`
	// Weaknesses       []Weakness    `json:"weaknesses"`
	Weaknesses        []any           `json:"weaknesses"`
	Configurations    []Configuration `json:"configurations,omitempty"`
	Affected          []NVDAffected   `json:"affected"`
	References        []ReferenceNVD  `json:"references"`
	AffectedFlattened []CpeMatch      `json:"affectedFlattened"`
}

type NVDAffected struct {
	Sources                      []CpeMatch `json:"sources"`
	Running_on                   []CpeMatch `json:"running-on"`
	Running_on_applications_only []CpeMatch `json:"running-on-applications-only"`
}

type Configuration struct {
	Nodes []Node `json:"nodes"`
}

type Node struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CpeMatch []CpeMatch `json:"cpematch"`
	Children []Node     `json:"children"`
}

type CpeMatch struct {
	Vulnerable            bool         `json:"vulnerable"`
	Criteria              string       `json:"criteria"`
	MatchCriteriaId       string       `json:"matchCriteriaId"`
	VersionEndIncluding   string       `json:"versionEndIncluding"`
	VersionEndExcluding   string       `json:"versionEndExcluding"`
	VersionStartIncluding string       `json:"versionStartIncluding"`
	VersionStartExcluding string       `json:"versionStartExcluding"`
	CriteriaDict          CriteriaDict `json:"criteriaDict"`
}

type CriteriaDict struct {
	Part       string `json:"part"`
	Vendor     string `json:"vendor"`
	Product    string `json:"product"`
	Version    string `json:"version"`
	Update     string `json:"update"`
	Edition    string `json:"edition"`
	Language   string `json:"language"`
	Sw_edition string `json:"sw_edition"`
	Target_sw  string `json:"target_sw"`
	Target_hw  string `json:"target_hw"`
	Other      string `json:"other"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Weakness struct {
	Source       string        `json:"source"`
	Type         string        `json:"type"`
	Descriptions []Description `json:"descriptions"`
	// Description  []Description `json:"_"`
}

type ReferenceNVD struct {
	Url    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

func GetVulns(nvd NVD) []CVE {
	var vulns []CVE

	// We iterate over the vulnerabilities and create a new CVE object
	for key := range nvd.Vulnerabilities {
		cve := nvd.Vulnerabilities[key]["cve"]
		// We set the key to the id so we can use it as a key in the database
		cve.Key = cve.Id
		cve.Affected = createAffected(cve)

		// We flatten the affected array so we can easily query it
		var flattened []CpeMatch
		if len(cve.Affected) != 0 {
			flattened = append(flattened, cve.Affected[0].Sources...)
			flattened = append(flattened, cve.Affected[0].Running_on...)
			flattened = append(flattened, cve.Affected[0].Running_on_applications_only...)
		}
		cve.AffectedFlattened = flattened

		for i, reference := range cve.References {
			if reference.Tags == nil {
				cve.References[i].Tags = make([]string, 0)
			}
		}

		// We dont need the configurations anymore
		cve.Configurations = nil
		vulns = append(vulns, cve)
	}

	return vulns
}

func createAffected(cve CVE) []NVDAffected {
	var affected []NVDAffected

	// See why configurations is now an array
	if len(cve.Configurations) > 0 {
		for _, config := range cve.Configurations[0].Nodes {
			// Three entries to fill: the actual source that is vulnerable, secondly what its running on and lastly running on but only applications
			// Example:
			//   source: bootstrap
			//   running-on: django, windows
			//   running-on-applicaitons-only: django

			if config.Operator == "AND" {
				if len(config.Children) < 2 {
					if len(config.CpeMatch) > 0 {
						sources := config.CpeMatch

						for source := range sources {
							sources[source].CriteriaDict = parseConfig(sources[source])
						}

						if validateLibrary(sources) {
							affected = append(affected, NVDAffected{
								Sources:                      filterCpe(sources),
								Running_on:                   []CpeMatch{},
								Running_on_applications_only: []CpeMatch{},
							})
						}
					}
				} else {
					running_on := config.Children[1].CpeMatch
					sources := config.Children[0].CpeMatch

					for run_on := range running_on {
						running_on[run_on].CriteriaDict = parseConfig(running_on[run_on])
					}

					for source := range sources {
						sources[source].CriteriaDict = parseConfig(sources[source])
					}

					// We only insert the affected object into the report if the report is about a library / application that is vulnerable
					// We dont care about vulnerabilities about hardware systems or operating systems
					if validateLibrary(sources) {
						affected = append(affected, NVDAffected{
							Sources:                      filterCpe(sources),
							Running_on:                   running_on,
							Running_on_applications_only: filterCpe(running_on),
						})
					}
				}
			} else if config.Operator == "OR" {
				sources := config.CpeMatch
				for source := range sources {
					sources[source].CriteriaDict = parseConfig(sources[source])
				}

				// We only insert the affected object into the report if the report is about a library / application that is vulnerable
				// We dont care about vulnerabilities about hardware systems or operating systems
				if validateLibrary(sources) {
					affected = append(affected, NVDAffected{
						Sources:                      filterCpe(sources),
						Running_on:                   []CpeMatch{},
						Running_on_applications_only: []CpeMatch{},
					})
				}
			}
		}
	}

	return affected
}

func parseConfig(config CpeMatch) CriteriaDict {
	// parsed_cpe = cpe_parser(config["cpe23Uri"])
	// config["cpe23Wfn"] = parsed_cpe.as_wfn()
	criteria_string := strings.Split(config.Criteria, ":")
	criteria := CriteriaDict{
		Part:       criteria_string[2],
		Vendor:     criteria_string[3],
		Product:    criteria_string[4],
		Version:    criteria_string[5],
		Update:     criteria_string[6],
		Edition:    criteria_string[7],
		Language:   criteria_string[8],
		Sw_edition: criteria_string[9],
		Target_sw:  criteria_string[10],
		Target_hw:  criteria_string[11],
		Other:      criteria_string[12],
	}

	return criteria
}

// checks if the vulnerability is for a library or not
func validateLibrary(sources []CpeMatch) bool {

	for _, source := range sources {
		// a stands for application
		// o stands for operating system
		// h stands for hardware
		if source.CriteriaDict.Part == "a" {
			return true
		}
	}
	return false
}

func filterCpe(sources []CpeMatch) []CpeMatch {
	var application_cpes []CpeMatch

	for _, source := range sources {
		// a stands for application
		// o stands for operating system
		// h stands for hardware
		if source.CriteriaDict.Part == "a" {
			application_cpes = append(application_cpes, source)
		}
	}
	return application_cpes
}
