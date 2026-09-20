package releaseid

import "strings"

// CompareLegacyTag orders two historical v-prefixed tags, -1 / 0 / +1.
//
// This is a SEPARATE RULE from CompareProductVersion, not the same rule with a
// flag. A legacy tag may carry a prerelease and a product version may not; the
// legacy ordering is the project's historical release order, and the product
// ordering is plain integer segments. Merging them would mean one of the two
// schemes inherits assumptions that were only ever true of the other.
//
// The rule: numeric segments first (compared as numbers, never as strings, so
// 0.0.10 is above 0.0.9), then a release above its own prereleases, then the
// prerelease identifiers. An identifier with no dot is the shape this project
// actually published — "beta11" is one identifier, not "beta.11" — so the digits
// at its end are compared NUMERICALLY. Comparing "beta9" and "beta11" as strings
// puts beta9 above beta11, which is how a real upgrade gets refused as a
// downgrade.
//
// Inputs are historical tags, already known to be well-formed; this is an
// ordering, not a validator.
func CompareLegacyTag(a, b string) int {
	left, leftPre, _ := strings.Cut(strings.TrimPrefix(a, "v"), "-")
	right, rightPre, _ := strings.Cut(strings.TrimPrefix(b, "v"), "-")

	leftSegments, rightSegments := strings.Split(left, "."), strings.Split(right, ".")
	for i := 0; i < len(leftSegments) && i < len(rightSegments); i++ {
		if c := compareNumericStrings(leftSegments[i], rightSegments[i]); c != 0 {
			return c
		}
	}
	if len(leftSegments) != len(rightSegments) {
		return sign(len(leftSegments) - len(rightSegments))
	}

	switch {
	case leftPre == rightPre:
		return 0
	case leftPre == "":
		return 1 // a release outranks its own prereleases
	case rightPre == "":
		return -1
	}

	leftIDs, rightIDs := strings.Split(leftPre, "."), strings.Split(rightPre, ".")
	for i := 0; i < len(leftIDs) && i < len(rightIDs); i++ {
		leftNumeric, rightNumeric := allDigits(leftIDs[i]), allDigits(rightIDs[i])
		switch {
		case leftNumeric && rightNumeric:
			if c := compareNumericStrings(leftIDs[i], rightIDs[i]); c != 0 {
				return c
			}
		case leftNumeric != rightNumeric:
			// A numeric identifier ranks below an alphanumeric one.
			if leftNumeric {
				return -1
			}
			return 1
		default:
			if c := comparePrereleaseIdentifier(leftIDs[i], rightIDs[i]); c != 0 {
				return c
			}
		}
	}
	return sign(len(leftIDs) - len(rightIDs))
}

// comparePrereleaseIdentifier orders two alphanumeric prerelease identifiers the
// way a reader would: the shared alphabetic prefix first, then the number after
// it as a number.
func comparePrereleaseIdentifier(a, b string) int {
	aPrefix, aDigits := splitTrailingDigits(a)
	bPrefix, bDigits := splitTrailingDigits(b)
	if c := strings.Compare(aPrefix, bPrefix); c != 0 {
		return c
	}
	if aDigits == "" || bDigits == "" {
		// One has a numeric suffix the other lacks; comparing whole identifiers
		// keeps "alpha" below "alpha1".
		return strings.Compare(a, b)
	}
	return compareNumericStrings(aDigits, bDigits)
}

// splitTrailingDigits separates an identifier into its leading text and its
// trailing run of digits.
func splitTrailingDigits(s string) (string, string) {
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	return s[:i], s[i:]
}

func allDigits(s string) bool { return s != "" && strings.Trim(s, "0123456789") == "" }

// compareNumericStrings orders two digit strings by value. Length first, so a
// number too large for int64 still compares correctly instead of overflowing.
func compareNumericStrings(a, b string) int {
	if len(a) != len(b) {
		return sign(len(a) - len(b))
	}
	return strings.Compare(a, b)
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}
