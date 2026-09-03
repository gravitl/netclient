package posture

import "strings"

// isMachineAccount reports Windows SAM-style machine/service accounts that
// must not be used as a posture user identity.
func isMachineAccount(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if strings.HasSuffix(value, "$") {
		return true
	}
	if idx := strings.LastIndex(value, "@"); idx > 0 && strings.Contains(value[:idx], "$") {
		return true
	}
	upper := strings.ToUpper(value)
	switch {
	case strings.HasPrefix(upper, "WORKGROUP\\"),
		strings.HasPrefix(upper, "NT AUTHORITY\\"),
		strings.HasPrefix(upper, "NT SERVICE\\"),
		strings.HasPrefix(upper, "WINDOW MANAGER\\"):
		return true
	}
	return false
}

// isValidUserEmail returns true for a human UPN/email suitable for MDM matching.
func isValidUserEmail(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || isMachineAccount(value) {
		return false
	}
	at := strings.LastIndex(value, "@")
	if at <= 0 || at >= len(value)-1 {
		return false
	}
	if strings.Contains(value[:at], "$") {
		return false
	}
	domain := value[at+1:]
	return strings.Contains(domain, ".") && !strings.Contains(value, " ")
}

// parseExecutingAccountName extracts a UPN from dsregcmd's comma-separated
// "Executing Account Name" value, e.g.
// "AzureAD\\user, user@tenant.onmicrosoft.com".
func parseExecutingAccountName(value string) string {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if isValidUserEmail(part) {
			return part
		}
	}
	return ""
}

func firstValidUserEmail(values ...string) string {
	for _, value := range values {
		if isValidUserEmail(value) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
