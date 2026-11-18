package php

import "testing"

func TestComposerLicenseListBecomesAnOrExpression(t *testing.T) {
	pack := convertPackagistToKnowledge(&PackagistPackage{Package: PackagistPackageDetails{
		Name: "acme/dual",
		Versions: map[string]PackagistVersionInfo{
			"1.0.0": {Version: "1.0.0", Time: "2020-01-01T00:00:00+00:00", License: []any{"MIT", "GPL-2.0-or-later"}},
			"0.9.0": {Version: "0.9.0", Time: "2019-01-01T00:00:00+00:00", License: []any{"MIT"}},
			"0.1.0": {Version: "0.1.0", Time: "2018-01-01T00:00:00+00:00"},
		},
	}})

	got := map[string]any{}
	for _, v := range pack.Versions {
		got[v.Version] = v.Extra["license_expression"]
	}
	if got["1.0.0"] != "MIT OR GPL-2.0-or-later" {
		t.Errorf("1.0.0 license = %v, want MIT OR GPL-2.0-or-later", got["1.0.0"])
	}
	if got["0.9.0"] != "MIT" {
		t.Errorf("0.9.0 license = %v, want MIT", got["0.9.0"])
	}
	if got["0.1.0"] != nil {
		t.Errorf("0.1.0 license = %v, want nothing stored", got["0.1.0"])
	}
	if pack.License != "MIT OR GPL-2.0-or-later" {
		t.Errorf("package license = %q, want MIT OR GPL-2.0-or-later", pack.License)
	}
}
