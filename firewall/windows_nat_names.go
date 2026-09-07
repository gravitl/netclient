package firewall

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

const netNatNamePrefix = "nm-eg-"

// netNatName returns a Windows NetNat-safe name derived from an egress ID.
// NetNat names should be short and alphanumeric-friendly.
func netNatName(egressID string) string {
	id := strings.TrimSpace(egressID)
	if id == "" {
		id = "unknown"
	}
	sum := sha1.Sum([]byte(id))
	return fmt.Sprintf("%s%s", netNatNamePrefix, hex.EncodeToString(sum[:8]))
}

// isNetmakerNetNatName reports whether name was created by netclient.
func isNetmakerNetNatName(name string) bool {
	return strings.HasPrefix(name, netNatNamePrefix)
}
