package firewall

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
)

func winAclIDHash(aclID string) string {
	sum := sha1.Sum([]byte(strings.TrimSpace(aclID)))
	return hex.EncodeToString(sum[:8])
}
