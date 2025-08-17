package php_security

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConvertFriendsOfPHPToOSV(t *testing.T) {
	advisory := FriendsOfPHPAdvisory{
		Title:       "Test Security Advisory",
		CVE:         "CVE-2024-TEST-001",
		Link:        "https://example.com/advisory",
		Reference:   "https://example.com/reference",
		Composer:    "vendor/package",
		Description: "Test advisory description",
		Branches: map[string]AdvisoryBranch{
			"main": {
				Versions: []string{"1.0.0", "1.1.0"},
				Time:     "2024-01-01",
			},
		},
	}

	result := convertFriendsOfPHPToOSV("vendor/package/001", advisory)

	assert.Equal(t, "FRIENDSOFPHP-vendor/package/001", result.Id)
	assert.Equal(t, "Test Security Advisory", result.Summary)
	assert.Equal(t, "Test advisory description", result.Details)
	assert.Contains(t, result.Aliases, "CVE-2024-TEST-001")
	assert.Equal(t, "Packagist", result.Affected[0].Package.Ecosystem)
	assert.Equal(t, "vendor/package", result.Affected[0].Package.Name)
	assert.Len(t, result.References, 2)
}

func TestConvertPHPCoreToOSV(t *testing.T) {
	vuln := PHPCoreVulnerability{
		CVE:         "CVE-2024-PHP-001",
		Summary:     "Test PHP Core Vulnerability",
		Description: "Test vulnerability in PHP core",
		Published:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Modified:    time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
		Severity:    "HIGH",
		CVSS:        8.5,
		References:  []string{"https://php.net/security"},
		Versions:    []string{"< 8.3.0"},
	}

	result := convertPHPCoreToOSV(vuln)

	assert.Equal(t, "CVE-2024-PHP-001", result.Id)
	assert.Equal(t, "Test PHP Core Vulnerability", result.Summary)
	assert.Equal(t, "Test vulnerability in PHP core", result.Details)
	assert.Contains(t, result.Aliases, "CVE-2024-PHP-001")
	assert.Equal(t, "PHP-Core", result.Affected[0].Package.Ecosystem)
	assert.Equal(t, "php", result.Affected[0].Package.Name)
	assert.Len(t, result.Severity, 1)
	assert.Equal(t, "8.5", result.Severity[0].Score)
}

func TestFriendsOfPHPAdvisoryJSONUnmarshal(t *testing.T) {
	jsonData := `{
		"title": "Test Advisory",
		"cve": "CVE-2024-001",
		"link": "https://example.com",
		"reference": "https://ref.example.com",
		"composer": "test/package",
		"branches": {
			"main": {
				"versions": ["1.0.0", "1.1.0"],
				"time": "2024-01-01"
			}
		}
	}`

	var advisory FriendsOfPHPAdvisory
	err := json.Unmarshal([]byte(jsonData), &advisory)

	assert.NoError(t, err)
	assert.Equal(t, "Test Advisory", advisory.Title)
	assert.Equal(t, "CVE-2024-001", advisory.CVE)
	assert.Equal(t, "test/package", advisory.Composer)
	assert.Contains(t, advisory.Branches, "main")
	assert.Equal(t, []string{"1.0.0", "1.1.0"}, advisory.Branches["main"].Versions)
}

func TestCreateSamplePHPCoreVulnerabilities(t *testing.T) {
	vulns := createSamplePHPCoreVulnerabilities("php")

	assert.Len(t, vulns, 1)
	assert.Contains(t, vulns[0].CVE, "CVE-2024-PHP-001")
	assert.Equal(t, "HIGH", vulns[0].Severity)
	assert.Equal(t, 7.5, vulns[0].CVSS)
	assert.Contains(t, vulns[0].Versions, "< 8.3.0")
}