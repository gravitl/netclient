package functions

import (
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gravitl/netmaker/schema"
	"golang.org/x/exp/slog"
)

// After an intentional host leave (tenant switch / Desktop logout unregister),
// the server publishes DELETE_HOST over MQTT — often immediately, before the
// leave HTTP returns, and again after the next tenant session is up. Handling
// that echo ForceLogouts and wipes enrollment — ignore echoes for the left
// identity for a short window. Same-tenant admin DELETE_HOST still applies.
// Callers must ArmIgnoreStaleDeleteHost BEFORE the leave HTTP request.
const staleDeleteHostGrace = 2 * time.Minute

var (
	deleteHostGuardMu     sync.Mutex
	ignoreDeleteHostUntil int64 // unix nano; 0 = not armed
	ignoredTenantID       string
	ignoredHostID         string
)

// ArmIgnoreStaleDeleteHost suppresses DELETE_HOST ForceLogout / local teardown
// for staleDeleteHostGrace when the message matches tenantID (and hostID when
// non-empty). Safe to call repeatedly; extends the window and replaces identity.
// Must be called before leaveHostOnTenant / unregister HTTP so an immediate
// MQTT echo cannot race past the ignore. Pass the tenant (and host) being left,
// captured before clearLocalEnrollmentAfterTenantLeave.
func ArmIgnoreStaleDeleteHost(tenantID, hostID string) {
	tenantID = strings.TrimSpace(tenantID)
	hostID = strings.TrimSpace(hostID)
	until := time.Now().Add(staleDeleteHostGrace).UnixNano()
	deleteHostGuardMu.Lock()
	ignoreDeleteHostUntil = until
	ignoredTenantID = tenantID
	ignoredHostID = hostID
	deleteHostGuardMu.Unlock()
	slog.Info("armed DELETE_HOST ignore window",
		"duration", staleDeleteHostGrace.String(),
		"tenant", tenantID, "host", hostID)
}

// ShouldIgnoreStaleDeleteHost reports whether a DELETE_HOST should be treated as
// the echo of an intentional leave rather than an admin/server eviction.
// Only messages whose host matches the armed left-tenant (and host ID when set)
// are suppressed; genuine same-tenant evictions proceed.
func ShouldIgnoreStaleDeleteHost(host schema.Host) bool {
	deleteHostGuardMu.Lock()
	defer deleteHostGuardMu.Unlock()

	until := ignoreDeleteHostUntil
	if until == 0 {
		return false
	}
	now := time.Now().UnixNano()
	if now > until {
		ignoreDeleteHostUntil = 0
		ignoredTenantID = ""
		ignoredHostID = ""
		return false
	}

	msgTenant := strings.TrimSpace(host.TenantID)
	if ignoredTenantID == "" || msgTenant == "" || msgTenant != ignoredTenantID {
		return false
	}
	if ignoredHostID != "" {
		msgHostID := host.ID.String()
		if host.ID == uuid.Nil || msgHostID != ignoredHostID {
			return false
		}
	}
	return true
}
