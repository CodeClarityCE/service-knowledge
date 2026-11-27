package php

import (
	"os"
	"testing"
)

// The fixture is smarty/smarty's Packagist v2 response, trimmed: each version lists only
// what differs from the one before it, and v4.6.1 is the newest release but not the first entry.
func loadSmarty(t *testing.T) *PackagistPackage {
	t.Helper()
	body, err := os.ReadFile("testdata/smarty-minified.json")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parsePackagist("smarty/smarty", body)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestMinifiedVersionsInheritTheLicenseOfTheVersionBefore(t *testing.T) {
	pack := convertPackagistToKnowledge(loadSmarty(t))

	got := map[string]any{}
	for _, v := range pack.Versions {
		got[v.Version] = v.Extra["license_expression"]
	}
	want := map[string]string{
		"v5.9.1": "LGPL-3.0", "v5.9.0": "LGPL-3.0", "v4.6.1": "LGPL-3.0", "v4.3.0": "LGPL-3.0",
		"v3.1.34": "LGPL-3.0", "v2.6.33": "LGPL-2.1", "v2.6.31": "LGPL-2.1",
	}
	for version, license := range want {
		if got[version] != license {
			t.Errorf("%s license = %v, want %s", version, got[version], license)
		}
	}
}

func TestPackageLicenseComesFromTheNewestReleaseWhenItIsMinified(t *testing.T) {
	pack := convertPackagistToKnowledge(loadSmarty(t))

	if pack.LatestVersion != "v4.6.1" {
		t.Fatalf("latest version = %q, want v4.6.1", pack.LatestVersion)
	}
	if pack.License != "LGPL-3.0" {
		t.Errorf("package license = %q, want LGPL-3.0", pack.License)
	}
	if pack.Description != "Smarty - the compiling PHP template engine" {
		t.Errorf("package description = %q, want the inherited one", pack.Description)
	}
}

func TestUnsetRemovesAnInheritedField(t *testing.T) {
	parsed := loadSmarty(t)

	if parsed.Package.Versions["v4.3.0"].Funding == nil {
		t.Error("v4.3.0 should inherit funding from v5.9.1")
	}
	if funding := parsed.Package.Versions["v3.1.34"].Funding; funding != nil {
		t.Errorf("v3.1.34 funding = %v, want it unset", funding)
	}
	if funding := parsed.Package.Versions["v2.6.31"].Funding; funding != nil {
		t.Errorf("v2.6.31 funding = %v, want it to stay unset", funding)
	}
}
