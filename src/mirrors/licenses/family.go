package licenses

import "strings"

// Id prefixes of the copyleft and permissive license families, compared without case.
var (
	copyleftPrefixes   = []string{"GPL-", "LGPL-", "AGPL-", "EPL-", "EUPL-", "CDDL-"}
	permissivePrefixes = []string{"MIT-", "BSD-", "APACHE-", "ISC-", "ZLIB-"}
	permissiveIDs      = []string{"MIT", "ISC", "ZLIB", "BLUEOAK-1.0.0"}
	// BSD-Protection carries share-alike terms, so it is not called permissive.
	unclassifiedIDs = []string{"BSD-PROTECTION"}
)

// licenseFamily returns "copyleft" or "permissive" for an SPDX id in a known family, or "".
func licenseFamily(id string) string {
	upper := strings.ToUpper(id)
	if hasAny(upper, unclassifiedIDs, false) {
		return ""
	}
	if hasAny(upper, copyleftPrefixes, true) {
		return "copyleft"
	}
	if hasAny(upper, permissiveIDs, false) || hasAny(upper, permissivePrefixes, true) {
		return "permissive"
	}
	return ""
}

// hasAny reports whether id equals, or with prefix set starts with, one of the values.
func hasAny(id string, values []string, prefix bool) bool {
	for _, v := range values {
		if id == v || (prefix && strings.HasPrefix(id, v)) {
			return true
		}
	}
	return false
}
