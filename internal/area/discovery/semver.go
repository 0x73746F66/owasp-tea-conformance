package discovery

import (
	"strconv"
	"strings"
)

// Version is a SemVer 2.0.0 version, parsed only as far as precedence needs.
//
// The specification tells a client to pick the endpoint advertising the highest
// version it supports "based on SemVer 2.0.0 comparison rules", so this has to
// be real precedence and not a string sort: TEA has shipped versions like
// 0.1.0-beta.1 and 0.2.0-beta.2, and "0.10.0" sorts before "0.9.0" as text.
type Version struct {
	Raw        string
	Major      int
	Minor      int
	Patch      int
	PreRelease []string
	Valid      bool
}

// ParseVersion parses a version string. An unparseable string is returned with
// Valid false rather than as an error: a provider advertising a version this
// suite cannot parse is a finding to report, not a reason to abandon the run.
func ParseVersion(s string) Version {
	v := Version{Raw: s}
	core := strings.TrimSpace(s)
	if core == "" {
		return v
	}
	// A leading "v" is not SemVer; the discovery schema forbids it, and the
	// discovery area reports it. Parsing tolerantly here means the report says
	// "carries a v prefix" rather than "unparseable".
	core = strings.TrimPrefix(core, "v")

	if i := strings.IndexByte(core, '+'); i >= 0 {
		core = core[:i] // build metadata is ignored for precedence
	}
	if i := strings.IndexByte(core, '-'); i >= 0 {
		v.PreRelease = strings.Split(core[i+1:], ".")
		core = core[:i]
	}
	// SemVer requires all three of major, minor and patch. "1.0" is a common
	// and reasonable-looking thing to advertise, and it is not a version the
	// specification's selection rule can be applied to — so it is reported
	// rather than quietly padded to 1.0.0.
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return v
	}
	nums := make([]int, 3)
	for i := range parts {
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return v
		}
		nums[i] = n
	}
	v.Major, v.Minor, v.Patch = nums[0], nums[1], nums[2]
	v.Valid = true
	return v
}

// Compare returns -1, 0 or 1 following SemVer 2.0.0 precedence. Unparseable
// versions sort below every parseable one.
func Compare(a, b Version) int {
	switch {
	case !a.Valid && !b.Valid:
		return strings.Compare(a.Raw, b.Raw)
	case !a.Valid:
		return -1
	case !b.Valid:
		return 1
	}
	for _, pair := range [][2]int{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}} {
		if pair[0] != pair[1] {
			if pair[0] < pair[1] {
				return -1
			}
			return 1
		}
	}
	// A version with a pre-release has lower precedence than one without.
	switch {
	case len(a.PreRelease) == 0 && len(b.PreRelease) == 0:
		return 0
	case len(a.PreRelease) == 0:
		return 1
	case len(b.PreRelease) == 0:
		return -1
	}
	for i := 0; i < len(a.PreRelease) && i < len(b.PreRelease); i++ {
		if c := comparePreReleaseIdentifier(a.PreRelease[i], b.PreRelease[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(a.PreRelease) < len(b.PreRelease):
		return -1
	case len(a.PreRelease) > len(b.PreRelease):
		return 1
	}
	return 0
}

func comparePreReleaseIdentifier(a, b string) int {
	an, aErr := strconv.Atoi(a)
	bn, bErr := strconv.Atoi(b)
	switch {
	case aErr == nil && bErr == nil:
		if an != bn {
			if an < bn {
				return -1
			}
			return 1
		}
		return 0
	case aErr == nil:
		// Numeric identifiers always have lower precedence than alphanumeric.
		return -1
	case bErr == nil:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

// SameMajorMinor reports whether two versions are the same TEA API generation,
// which is what "this endpoint speaks the specification I validated against"
// means in practice.
func SameMajorMinor(a, b Version) bool {
	return a.Valid && b.Valid && a.Major == b.Major && a.Minor == b.Minor
}
