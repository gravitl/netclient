package wireguard

import (
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestSetUnhealthyInvokesOnIGWUnhealthyHook(t *testing.T) {
	prev := OnIGWUnhealthy
	t.Cleanup(func() { OnIGWUnhealthy = prev })

	done := make(chan string, 1)
	OnIGWUnhealthy = func(pk string) { done <- pk }

	s := &igwStatus{publicKey: "peer-key-abc"}
	s.isHealthy.Store(true)
	s.setUnhealthy(nil)
	if s.isHealthy.Load() {
		t.Fatal("expected unhealthy")
	}
	select {
	case pk := <-done:
		if pk != "peer-key-abc" {
			t.Fatalf("hook public key = %q", pk)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnIGWUnhealthy was not called")
	}
}

// Failover talks to the API, which needs DNS switched back to split mode first.
func TestSetUnhealthyReappliesDNSBeforeFailover(t *testing.T) {
	prevRouting, prevUnhealthy := OnIGWRoutingChanged, OnIGWUnhealthy
	t.Cleanup(func() { OnIGWRoutingChanged, OnIGWUnhealthy = prevRouting, prevUnhealthy })

	order := make(chan string, 2)
	OnIGWRoutingChanged = func() { order <- "dns" }
	OnIGWUnhealthy = func(string) { order <- "failover" }

	s := &igwStatus{publicKey: "peer-key-abc"}
	s.isHealthy.Store(true)
	s.setUnhealthy(nil)
	for _, want := range []string{"dns", "failover"} {
		select {
		case got := <-order:
			if got != want {
				t.Fatalf("hook order: got %q, want %q", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("hook %q was not called", want)
		}
	}
}

func TestRejectedIGW(t *testing.T) {
	m := &IGWMonitor{}
	gw4 := net.ParseIP("100.64.0.1")
	if m.RejectedIGW(gw4, nil) {
		t.Fatal("empty monitor rejected a nexthop")
	}
	m.status = &igwStatus{gw4: gw4}
	m.status.isHealthy.Store(true)
	if m.RejectedIGW(gw4, nil) {
		t.Fatal("healthy current IGW reported as rejected")
	}
	m.status.isHealthy.Store(false)
	if !m.RejectedIGW(gw4, nil) {
		t.Fatal("unhealthy current IGW not rejected")
	}
	if m.RejectedIGW(net.ParseIP("100.64.0.2"), nil) {
		t.Fatal("different nexthop reported as rejected")
	}
	if !m.IsCurrentIGW(gw4, nil) {
		t.Fatal("unhealthy IGW should still count as current so peer-updates skip reinstall")
	}
}

// A single failed sample must never tear exit routing down: every iface rebuild
// has a window where the device is up with no peers configured yet.
func TestNoHandshakeDeclaresUnhealthyAfterGrace(t *testing.T) {
	s := &igwStatus{startedAt: time.Now()}
	s.isHealthy.Store(true)
	var peer wgtypes.Peer
	if got := s.noHandshakeAction(peer); got != "grace" {
		t.Fatalf("no handshake during grace = %q, want grace", got)
	}

	s.startedAt = time.Now().Add(-2 * IGWStartupGrace)
	if got := s.noHandshakeAction(peer); got != "unhealthy" {
		t.Fatalf("no handshake after grace = %q, want unhealthy", got)
	}

	peer.LastHandshakeTime = time.Now()
	if got := s.noHandshakeAction(peer); got != "" {
		t.Fatalf("peer with a handshake = %q, want normal checks", got)
	}
}

// A black-holed exit can keep its WireGuard handshake fresh via keepalives while
// the overlay VPN-IP probe times out. That probe failure must count even when the
// peer has never answered a probe before — otherwise the exit stays "healthy"
// and desktop never clears it.
func TestFailedOverlayProbeCountsWithoutPriorSuccess(t *testing.T) {
	s := &igwStatus{
		startedAt: time.Now().Add(-2 * IGWStartupGrace),
		gw4:       net.ParseIP("100.64.0.1"),
	}
	s.isHealthy.Store(true)
	peer := wgtypes.Peer{LastHandshakeTime: time.Now()}

	for i := 0; i < IGWFailureThreshold; i++ {
		// No rx movement: dead-exit path must still count failures.
		s.applyOverlayProbeResult(peer, false, false)
	}
	if s.isHealthy.Load() {
		t.Fatal("failed overlay probes left the exit healthy")
	}
	if s.probeEverSucceeded {
		t.Fatal("probeEverSucceeded set after only failures")
	}
}

// A live exit whose metrics port is firewalled still moves the WireGuard
// receive counter. That must not tear the gateway down.
func TestFailedOverlayProbeIgnoredWhenUnderlayFlows(t *testing.T) {
	s := &igwStatus{
		startedAt: time.Now().Add(-2 * IGWStartupGrace),
		gw4:       net.ParseIP("100.64.0.1"),
	}
	s.isHealthy.Store(true)
	peer := wgtypes.Peer{LastHandshakeTime: time.Now()}

	for i := 0; i < IGWFailureThreshold; i++ {
		s.applyOverlayProbeResult(peer, false, true)
	}
	if !s.isHealthy.Load() {
		t.Fatal("firewalled metrics port tore down a flowing underlay exit")
	}
	if s.failureCount != 0 {
		t.Fatalf("failureCount = %d, want 0", s.failureCount)
	}
}

// Underlay evidence must also heal an exit that was marked unhealthy while the
// metrics port stays firewalled (probe never returns ok).
func TestUnderlayFlowRecoversUnhealthyFirewalledExit(t *testing.T) {
	s := &igwStatus{
		startedAt: time.Now().Add(-2 * IGWStartupGrace),
		gw4:       net.ParseIP("100.64.0.1"),
		lastRx:    100,
	}
	s.isHealthy.Store(false)
	peer := wgtypes.Peer{LastHandshakeTime: time.Now()}

	for i := 0; i < IGWRecoveryThreshold; i++ {
		s.applyOverlayProbeResult(peer, false, true)
	}
	if !s.isHealthy.Load() {
		t.Fatal("firewalled exit did not recover from underlay traffic")
	}
}

func TestOverlayProbeSuccessClearsFailures(t *testing.T) {
	s := &igwStatus{
		startedAt:    time.Now().Add(-2 * IGWStartupGrace),
		failureCount: IGWFailureThreshold - 1,
		gw4:          net.ParseIP("100.64.0.1"),
	}
	s.isHealthy.Store(true)
	peer := wgtypes.Peer{LastHandshakeTime: time.Now()}
	s.applyOverlayProbeResult(peer, true, false)
	if !s.probeEverSucceeded {
		t.Fatal("probeEverSucceeded not set after success")
	}
	if s.failureCount != 0 {
		t.Fatalf("failureCount = %d after success, want 0", s.failureCount)
	}
}

func TestNoteFailureRespectsGraceAndThreshold(t *testing.T) {
	s := &igwStatus{startedAt: time.Now()}
	s.isHealthy.Store(true)

	s.noteFailure(nil)
	if !s.isHealthy.Load() || s.failureCount != 0 {
		t.Fatalf("failure counted during startup grace: healthy=%v count=%d", s.isHealthy.Load(), s.failureCount)
	}

	s.startedAt = time.Now().Add(-2 * IGWStartupGrace)
	for i := 1; i < IGWFailureThreshold; i++ {
		s.noteFailure(nil)
		if !s.isHealthy.Load() {
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

// An interface carrying only link-local or loopback addresses cannot source
// overlay traffic, so the exit path is dead however alive the peer looks.
func TestAnySourceAddr(t *testing.T) {
	cases := []struct {
		name string
		ips  []string
		want bool
	}{
		{"overlay v4", []string{"100.121.42.9"}, true},
		{"overlay v6 ula", []string{"fd3c:1a93:2fa8:7ba5::9"}, true},
		{"link-local only", []string{"fe80::1"}, false},
		{"loopback only", []string{"127.0.0.1"}, false},
		{"unspecified only", []string{"0.0.0.0"}, false},
		{"none", nil, false},
		{"link-local plus overlay", []string{"fe80::1", "100.121.42.9"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ips := make([]net.IP, 0, len(tc.ips))
			for _, s := range tc.ips {
				ip := net.ParseIP(s)
				if ip == nil {
					t.Fatalf("bad test ip %q", s)
				}
				ips = append(ips, ip)
			}
			if got := anySourceAddr(ips); got != tc.want {
				t.Fatalf("anySourceAddr(%v) = %v, want %v", tc.ips, got, tc.want)
			}
		})
	}
}

func TestShouldBlockIPv6Leak(t *testing.T) {
	v4 := net.ParseIP("100.121.42.5")
	v6 := net.ParseIP("fd3c:1a93:2fa8:7ba5::5")
	cases := []struct {
		name string
		gw4  net.IP
		gw6  net.IP
		want bool
	}{
		{"ipv4-only exit", v4, nil, true},
		{"dual-stack exit", v4, v6, false},
		{"ipv6-only exit", nil, v6, false},
		{"no exit", nil, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldBlockIPv6Leak(tc.gw4, tc.gw6); got != tc.want {
				t.Fatalf("shouldBlockIPv6Leak(%v,%v)=%v want %v", tc.gw4, tc.gw6, got, tc.want)
			}
		})
	}
}
