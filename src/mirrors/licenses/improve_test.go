package licenses

import (
	"strings"
	"testing"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
)

func classify(ids ...string) map[string]knowledge.License {
	licenses := make([]knowledge.License, len(ids))
	for i, id := range ids {
		licenses[i].LicenseID = id
	}
	got := map[string]knowledge.License{}
	for _, l := range addCodeClarityInfo(licenses) {
		got[l.LicenseID] = l
	}
	return got
}

func TestCommonLicenseFamiliesAreClassified(t *testing.T) {
	want := map[string]string{
		"GPL-2.0":          "copyleft",
		"GPL-2.0-only":     "copyleft",
		"GPL-2.0-or-later": "copyleft",
		"GPL-3.0+":         "copyleft",
		"LGPL-2.1-only":    "copyleft",
		"AGPL-3.0-only":    "copyleft",
		"EPL-2.0":          "copyleft",
		"EUPL-1.2":         "copyleft",
		"CDDL-1.0":         "copyleft",
		"BlueOak-1.0.0":    "permissive",
		"BSD-4-Clause":     "permissive",
		"MIT-0":            "permissive",
		"Zlib":             "permissive",
		"Apache-2.0":       "permissive",
		"ISC":              "permissive",
	}
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	got := classify(ids...)
	for id, classification := range want {
		if got[id].Details.Classification != classification {
			t.Errorf("%s classification = %q, want %q", id, got[id].Details.Classification, classification)
		}
	}
}

func TestLicensesOutsideTheFamiliesStayUnclassified(t *testing.T) {
	got := classify("CC-BY-4.0", "LGPLLR", "BSD-Protection", "Artistic-2.0")
	for id, l := range got {
		if l.Details.Classification != "" {
			t.Errorf("%s classification = %q, want none", id, l.Details.Classification)
		}
	}
}

func TestHandWrittenLicensesKeepTheirClassificationAndDescription(t *testing.T) {
	want := map[string]string{
		"0BSD": "permissive", "Apache-1.0": "permissive", "Apache-1.1": "permissive", "Apache-2.0": "permissive",
		"BSD-1-Clause": "permissive", "BSD-2-Clause": "permissive", "BSD-3-Clause": "permissive",
		"ISC": "permissive", "MIT": "permissive", "MPL-1.0": "copyleft", "MPL-1.1": "copyleft",
		"MPL-2.0": "copyleft", "Unlicense": "permissive", "WTFPL": "permissive", "X11": "permissive",
	}
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	got := classify(ids...)
	for id, classification := range want {
		if got[id].Details.Classification != classification {
			t.Errorf("%s classification = %q, want %q", id, got[id].Details.Classification, classification)
		}
		if got[id].Details.Description == "" {
			t.Errorf("%s lost its description", id)
		}
	}
	if !strings.HasPrefix(got["MIT"].Details.Description, "The MIT license is a permissive open-source license") {
		t.Errorf("MIT description changed: %q", got["MIT"].Details.Description)
	}
}
