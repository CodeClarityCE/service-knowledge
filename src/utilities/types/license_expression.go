package types

import (
	"strings"

	"github.com/sirupsen/logrus"
)

// VersionLicenseKey is the version extra key that holds the version's SPDX license expression.
const VersionLicenseKey = "license_expression"

// AnyOfLicenses joins licenses a package offers as alternatives into one OR expression.
func AnyOfLicenses(licenses []string) string {
	var present []string
	for _, l := range licenses {
		if l = strings.TrimSpace(l); l != "" {
			present = append(present, l)
		}
	}
	if len(present) == 1 {
		return present[0]
	}
	parts := make([]string, len(present))
	for i, l := range present {
		// Keep a compound entry together inside the OR.
		if strings.Contains(l, " ") {
			l = "(" + l + ")"
		}
		parts[i] = l
	}
	return strings.Join(parts, " OR ")
}

// NpmLicenseExpression reads npm's license field, or the legacy licenses array, as one expression.
func NpmLicenseExpression(license any, licenses any) string {
	if expr := npmLicenseName(license); expr != "" {
		return expr
	}
	var names []string
	switch list := licenses.(type) {
	case []any:
		for _, l := range list {
			names = append(names, npmLicenseName(l))
		}
	case []LicenseNpm:
		for _, l := range list {
			names = append(names, l.Type)
		}
	default:
		names = append(names, npmLicenseName(licenses))
	}
	return AnyOfLicenses(names)
}

// npmLicenseName reads a license given as a string or as an object with a type.
func npmLicenseName(license any) string {
	switch l := license.(type) {
	case string:
		return strings.TrimSpace(l)
	case map[string]any:
		if t, ok := l["type"].(string); ok {
			return strings.TrimSpace(t)
		}
	case LicenseNpm:
		return strings.TrimSpace(l.Type)
	}
	return ""
}

// LegacyPackageLicenseLength is the package.license limit before the API's WidenPackageLicense migration.
const LegacyPackageLicenseLength = 50

// WarnLongPackageLicense logs a package license that a knowledge database without that migration would reject.
// The value is kept whole, since cutting an expression would change its meaning.
func WarnLongPackageLicense(name, language, license string) {
	if len(license) <= LegacyPackageLicenseLength {
		return
	}
	logrus.WithFields(logrus.Fields{
		"package":  name,
		"language": language,
		"length":   len(license),
	}).Warn("Package license is longer than 50 characters; the knowledge database needs the WidenPackageLicense migration to store it")
}
