package uiapi

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/hashicorp/go-version"
)

// MinDesktopServerVersion is the oldest Netmaker server this Desktop daemon
// refuses. Servers must be newer than this (v1.7.1+); v1.7.0 and below are
// incompatible with the NM-356 Desktop daemon.
const MinDesktopServerVersion = "v1.7.0"

// ErrCodeServerIncompatible is returned on POST /server and PUT /session when
// the target Netmaker server is too old for this Desktop build.
const ErrCodeServerIncompatible = "server_incompatible"

// IsDesktopServerCompatible reports whether a Netmaker server version can be
// used with this Desktop daemon (strictly newer than MinDesktopServerVersion).
// "dev" is always allowed. Unparseable versions are rejected.
func IsDesktopServerCompatible(ver string) bool {
	ver = strings.TrimSpace(ver)
	if ver == "" {
		return false
	}
	if ver == "dev" {
		return true
	}
	trimmed := strings.TrimFunc(ver, func(r rune) bool {
		return !unicode.IsNumber(r)
	})
	v, err := version.NewVersion(trimmed)
	if err != nil {
		return false
	}
	constraint, err := version.NewConstraint("> " + strings.TrimPrefix(MinDesktopServerVersion, "v"))
	if err != nil {
		return false
	}
	return constraint.Check(v)
}

func serverIncompatibleMessage(serverVersion string) string {
	found := strings.TrimSpace(serverVersion)
	if found == "" {
		found = "unknown"
	}
	return fmt.Sprintf(
		"Netmaker Desktop requires a server newer than %s (this server reports %s)",
		MinDesktopServerVersion, found)
}
