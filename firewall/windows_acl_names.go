package firewall

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
)

const (
	// Legacy Defender Firewall group/names — removed on upgrade; kept for cleanup only.
	winFwACLGroup       = "Netmaker-ACL"
	winFwDNSUDPRuleName = "Netmaker-DNS-UDP"
)

func winAclIDHash(aclID string) string {
	sum := sha1.Sum([]byte(strings.TrimSpace(aclID)))
	return hex.EncodeToString(sum[:8])
}
