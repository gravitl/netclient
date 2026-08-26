package wireguard

import (
	"net"
	"testing"
	"time"
)

// A single failed sample must never tear exit routing down: every iface rebuild
// has a window where the device is up with no peers configured yet.
func TestNoteFailureRespectsGraceAndThreshold(t *testing.T) {
	s := &igwStatus{isHealthy: true, startedAt: time.Now()}

	s.noteFailure(nil)
	if !s.isHealthy || s.failureCount != 0 {
		t.Fatalf("failure counted during startup grace: healthy=%v count=%d", s.isHealthy, s.failureCount)
	}

	s.startedAt = time.Now().Add(-2 * IGWStartupGrace)
	for i := 1; i < IGWFailureThreshold; i++ {
		s.noteFailure(nil)
		if !s.isHealthy {
			t.Fatalf("torn down after %d of %d failures", i, IGWFailureThreshold)
		}
	}
	if s.failureCount != IGWFailureThreshold-1 {
		t.Errorf("failureCount = %d, want %d", s.failureCount, IGWFailureThreshold-1)
	}
}

// Receive-counter progress is proof of life, but a fresh monitor and a counter
// reset by an iface rebuild must not be mistaken for it in either direction.
func TestNoteRx(t *testing.T) {
	s := &igwStatus{lastRx: -1}

	if s.noteRx(4096) {
		t.Error("first sample counted as progress despite having no baseline")
	}
	if !s.noteRx(8192) {
		t.Error("advancing counter not counted as progress")
	}
	if s.noteRx(8192) {
		t.Error("flat counter counted as progress")
	}
	if s.noteRx(512) {
		t.Error("counter reset counted as progress")
	}
	if !s.noteRx(1024) {
		t.Error("progress after a counter reset not counted, baseline not rebased")
	}
}

func TestBeginIfaceRebuildGatesChecks(t *testing.T) {
	if got := ifaceRebuilds.Load(); got != 0 {
		t.Fatalf("ifaceRebuilds = %d at start of test", got)
	}
	t.Cleanup(func() { igwRearmPending.Store(false) })

	outer := BeginIfaceRebuild()
	inner := BeginIfaceRebuild()

	outer()
	outer() // completing twice must not double-decrement
	if got := ifaceRebuilds.Load(); got != 1 {
		t.Errorf("ifaceRebuilds = %d while a rebuild is still in flight, want 1", got)
	}
	if igwRearmPending.Load() {
		t.Error("startup grace re-armed before the last rebuild finished")
	}

	inner()
	if got := ifaceRebuilds.Load(); got != 0 {
		t.Errorf("ifaceRebuilds = %d after all rebuilds finished", got)
	}
	if !igwRearmPending.Load() {
		t.Error("startup grace not re-armed after the rebuild finished")
	}
}

// After the monitor tears down OS exit routes (unhealthy), peer updates must not
// treat the gateway as "already installed" or traffic stays off-exit until pull.
func TestIsCurrentIGWRequiresHealthy(t *testing.T) {
	m := &IGWMonitor{}
	gw4 := net.ParseIP("10.0.0.1")

	if m.IsCurrentIGW(gw4, nil) {
		t.Fatal("empty monitor reported current IGW")
	}

	m.status = &igwStatus{gw4: gw4, isHealthy: true}
	if !m.IsCurrentIGW(gw4, nil) {
		t.Fatal("healthy monitor with matching nexthop should be current")
	}

	m.status.isHealthy = false
	if m.IsCurrentIGW(gw4, nil) {
		t.Fatal("unhealthy monitor must not report current IGW (forces SetInternetGw reapply)")
	}
}
