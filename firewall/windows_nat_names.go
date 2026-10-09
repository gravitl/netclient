package firewall

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
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

// normalizeNetNatPrefix returns the network-form CIDR for WinNAT
// (e.g. 100.110.0.2/24 -> 100.110.0.0/24). Invalid input is returned trimmed.
func normalizeNetNatPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "<nil>" {
		return ""
	}
	_, ipnet, err := net.ParseCIDR(prefix)
	if err != nil {
		return prefix
	}
	return ipnet.String()
}

// netNatPrefixesEqual reports whether two prefixes describe the same network.
func netNatPrefixesEqual(a, b string) bool {
	na, nb := normalizeNetNatPrefix(a), normalizeNetNatPrefix(b)
	if na == "" || nb == "" {
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	}
	return na == nb
}
