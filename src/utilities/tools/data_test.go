package tools

import (
	"encoding/json"
	"testing"

	"github.com/CodeClarityCE/service-knowledge/src/utilities/types"
)

// Decodes a packument the way the npm mirror receives it.
func packument(t *testing.T, raw string) types.Npm {
	t.Helper()
	var npm types.Npm
	if err := json.Unmarshal([]byte(raw), &npm); err != nil {
		t.Fatalf("decode packument: %v", err)
	}
	return npm
}

func versionLicenses(t *testing.T, raw string) map[string]any {
	t.Helper()
	pack := CreatePackageInfoNpm(packument(t, raw))
	got := map[string]any{}
	for _, v := range pack.Versions {
		got[v.Version] = v.Extra[types.VersionLicenseKey]
	}
	return got
}

func TestEachNpmVersionKeepsItsOwnLicense(t *testing.T) {
	got := versionLicenses(t, `{
		"name": "glob",
		"license": "BlueOak-1.0.0",
		"versions": {
			"7.1.2": {"version": "7.1.2", "license": "ISC"},
			"9.0.0": {"version": "9.0.0", "license": "BlueOak-1.0.0"}
		}
	}`)
	if got["7.1.2"] != "ISC" {
		t.Errorf("7.1.2 license = %v, want ISC", got["7.1.2"])
	}
	if got["9.0.0"] != "BlueOak-1.0.0" {
		t.Errorf("9.0.0 license = %v, want BlueOak-1.0.0", got["9.0.0"])
	}
}

func TestLegacyNpmLicenseFormsBecomeExpressions(t *testing.T) {
	got := versionLicenses(t, `{
		"name": "legacy",
		"versions": {
			"1.0.0": {"version": "1.0.0", "license": {"type": "MIT", "url": "https://x"}},
			"1.1.0": {"version": "1.1.0", "licenses": [{"type": "MIT"}, {"type": "Apache-2.0"}]},
			"1.2.0": {"version": "1.2.0"}
		}
	}`)
	if got["1.0.0"] != "MIT" {
		t.Errorf("object license = %v, want MIT", got["1.0.0"])
	}
	if got["1.1.0"] != "MIT OR Apache-2.0" {
		t.Errorf("licenses array = %v, want MIT OR Apache-2.0", got["1.1.0"])
	}
	if got["1.2.0"] != nil {
		t.Errorf("no license = %v, want nothing stored", got["1.2.0"])
	}
}

func TestNpmPackageLicenseReadsTheObjectForm(t *testing.T) {
	pack := CreatePackageInfoNpm(packument(t, `{"name": "old", "license": {"type": "ISC"}, "versions": {}}`))
	if pack.License != "ISC" {
		t.Errorf("package license = %q, want ISC", pack.License)
	}
}
