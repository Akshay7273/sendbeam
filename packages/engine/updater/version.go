package updater

import (
	"fmt"
	"strconv"
	"strings"
)

// Version represents a parsed SemVer 2.0.0 release version.
type Version struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
	Build      string
	IsDev      bool
	Raw        string
}

// ParseVersion parses a SemVer string (e.g. "1.4.0", "v1.5.0-beta.1", "dev").
func ParseVersion(s string) (Version, error) {
	raw := strings.TrimSpace(s)
	if raw == "" || strings.EqualFold(raw, "dev") || strings.EqualFold(raw, "unsigned-dev") {
		return Version{IsDev: true, Raw: raw}, nil
	}

	clean := strings.TrimPrefix(raw, "v")
	clean = strings.TrimPrefix(clean, "V")

	// Split build metadata
	build := ""
	if idx := strings.Index(clean, "+"); idx != -1 {
		build = clean[idx+1:]
		clean = clean[:idx]
	}

	// Split prerelease
	prerelease := ""
	if idx := strings.Index(clean, "-"); idx != -1 {
		prerelease = clean[idx+1:]
		clean = clean[:idx]
	}

	parts := strings.Split(clean, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return Version{}, fmt.Errorf("invalid semver format %q", raw)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil || major < 0 {
		return Version{}, fmt.Errorf("invalid major version %q in %q", parts[0], raw)
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil || minor < 0 {
		return Version{}, fmt.Errorf("invalid minor version %q in %q", parts[1], raw)
	}

	patch := 0
	if len(parts) == 3 {
		patch, err = strconv.Atoi(parts[2])
		if err != nil || patch < 0 {
			return Version{}, fmt.Errorf("invalid patch version %q in %q", parts[2], raw)
		}
	}

	return Version{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Prerelease: prerelease,
		Build:      build,
		IsDev:      false,
		Raw:        raw,
	}, nil
}

// String returns the normalized SemVer representation.
func (v Version) String() string {
	if v.IsDev {
		if v.Raw != "" {
			return v.Raw
		}
		return "dev"
	}
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Prerelease != "" {
		s += "-" + v.Prerelease
	}
	if v.Build != "" {
		s += "+" + v.Build
	}
	return s
}

// IsPrerelease returns true if this version has a prerelease label.
func (v Version) IsPrerelease() bool {
	return !v.IsDev && v.Prerelease != ""
}

// Compare compares two versions according to SemVer 2.0.0 precedence.
// Returns -1 if v < other, 0 if v == other, 1 if v > other.
func (v Version) Compare(other Version) int {
	if v.IsDev && other.IsDev {
		return 0
	}
	if v.IsDev {
		return -1
	}
	if other.IsDev {
		return 1
	}
	if v.Major != other.Major {
		if v.Major > other.Major {
			return 1
		}
		return -1
	}
	if v.Minor != other.Minor {
		if v.Minor > other.Minor {
			return 1
		}
		return -1
	}
	if v.Patch != other.Patch {
		if v.Patch > other.Patch {
			return 1
		}
		return -1
	}
	if v.Prerelease == "" && other.Prerelease != "" {
		return 1
	}
	if v.Prerelease != "" && other.Prerelease == "" {
		return -1
	}
	if v.Prerelease == "" && other.Prerelease == "" {
		return 0
	}
	return comparePrerelease(v.Prerelease, other.Prerelease)
}

// IsGreaterThan returns true if v > other according to SemVer 2.0.0 precedence.
func (v Version) IsGreaterThan(other Version) bool {
	return v.Compare(other) > 0
}

func comparePrerelease(p1, p2 string) int {
	parts1 := strings.Split(p1, ".")
	parts2 := strings.Split(p2, ".")

	minLen := len(parts1)
	if len(parts2) < minLen {
		minLen = len(parts2)
	}

	for i := 0; i < minLen; i++ {
		n1, err1 := strconv.Atoi(parts1[i])
		n2, err2 := strconv.Atoi(parts2[i])

		if err1 == nil && err2 == nil {
			if n1 != n2 {
				if n1 > n2 {
					return 1
				}
				return -1
			}
		} else if err1 == nil && err2 != nil {
			// Numeric identifier has lower precedence than string
			return -1
		} else if err1 != nil && err2 == nil {
			return 1
		} else {
			if parts1[i] != parts2[i] {
				if parts1[i] > parts2[i] {
					return 1
				}
				return -1
			}
		}
	}

	if len(parts1) > len(parts2) {
		return 1
	} else if len(parts1) < len(parts2) {
		return -1
	}
	return 0
}

// CompatibleWithChannel reports whether this version is allowed on the specified channel.
func (v Version) CompatibleWithChannel(ch Channel) bool {
	if v.IsDev {
		return ch == ChannelDev
	}
	switch ch {
	case ChannelStable:
		return !v.IsPrerelease()
	case ChannelBeta:
		return true // Beta channel tracks both stable and prereleases
	case ChannelDev:
		return true
	default:
		return false
	}
}
