package functions

import (
	"sync/atomic"
	"time"

	"golang.org/x/exp/slog"
)

// After an intentional host leave (tenant switch / Desktop logout unregister),
// the server publishes DELETE_HOST over MQTT. On Windows that message often
// arrives after the user has already logged into the next tenant. Handling it
// would ForceLogout and wipe the new enrollment — ignore it for a short window.
const staleDeleteHostGrace = 2 * time.Minute

var ignoreDeleteHostUntil atomic.Int64 // unix nano; 0 = not armed

// ArmIgnoreStaleDeleteHost suppresses DELETE_HOST ForceLogout / local teardown
// for staleDeleteHostGrace. Safe to call repeatedly; extends the window.
func ArmIgnoreStaleDeleteHost() {
	until := time.Now().Add(staleDeleteHostGrace).UnixNano()
	ignoreDeleteHostUntil.Store(until)
	slog.Info("armed DELETE_HOST ignore window", "duration", staleDeleteHostGrace.String())
}

// ShouldIgnoreStaleDeleteHost reports whether a DELETE_HOST should be treated as
// the echo of an intentional leave rather than an admin/server eviction.
func ShouldIgnoreStaleDeleteHost() bool {
	until := ignoreDeleteHostUntil.Load()
	if until == 0 {
		return false
	}
	now := time.Now().UnixNano()
	if now <= until {
		return true
	}
	ignoreDeleteHostUntil.CompareAndSwap(until, 0)
	return false
}
