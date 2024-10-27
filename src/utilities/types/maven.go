package types

type Maven struct {
	Name        string `xml:"name"`
	Description string `xml:"description"`
	Url         string `xml:"url"`
	Version     string `xml:"version"`
	Packaging   string `xml:"packaging"`

	SCM SCM `xml:"scm"`

	// Versions map[string]NpmVersion `json:"versions"`
	// License  any                   `json:"license"`
	Licenses []LicenseMaven `json:"licenses"`
}

type LicenseMaven struct {
	Name string `json:"name"`
	Url  string `json:"url"`
}

type SCM struct {
	Connection string `xml:"connection"`
	Developer  string `xml:"developerConnection"`
	Url        string `xml:"url"`
}
