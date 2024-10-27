package types

type Package struct {
	Key         string    `json:"_key"`
	Revision    string    `json:"Revision"`
	Name        string    `json:"Name"`
	Description string    `json:"Description"`
	Homepage    string    `json:"Homepage"`
	Version     string    `json:"Version"`
	Versions    []Version `json:"-"`
	Time        string    `json:"Time"`
	Keywords    []string  `json:"Keywords"`
	Source      Source    `json:"Source"`
	Licenses    []string  `json:"Licenses"`
	Extra       any       `json:"Extra"`
}

type Source struct {
	Url  string `json:"Url"`
	Type string `json:"Type"`
}

type Version struct {
	Key             string            `json:"_key"`
	Version         string            `json:"Version"`
	Time            string            `json:"Time"`
	Dependencies    map[string]string `json:"Dependencies"`
	DevDependencies map[string]string `json:"DevDependencies"`
	Licenses        []string          `json:"Licenses"`
	Extra           any               `json:"Extra"`
}
