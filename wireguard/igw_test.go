package wireguard

import (
	"net"
	"testing"
	"time"
)

func TestSetUnhealthyInvokesOnIGWUnhealthyHook(t *testing.T) {
	prev := OnIGWUnhealthy
	t.Cleanup(func() { OnIGWUnhealthy = prev })

	done := make(chan string, 1)
	OnIGWUnhealthy = func(pk string) { done <- pk }

	s := &igwStatus{isHealthy: true, publicKey: "peer-key-abc"}
	s.setUnhealthy(nil)
	if s.isHealthy {
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

	s := &igwStatus{isHealthy: true, publicKey: "peer-key-abc"}
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

func TestRefreshHealthyExitRoutes(t *testing.T) {
	prevPin, prevWin, prevReinstall := pinExitUnderlay, exitRoutesWinning, reinstallExitRoutes
	t.Cleanup(func() {
		pinExitUnderlay, exitRoutesWinning, reinstallExitRoutes = prevPin, prevWin, prevReinstall
	})

	gw4 := net.ParseIP("100.64.0.1")
	var pins, reinstalls int
	pinExitUnderlay = func(string) { pins++ }
	reinstallExitRoutes = func(publicKey string, got4, got6 net.IP) error {
		reinstalls++
		if publicKey != "peer" || !got4.Equal(gw4) || got6 != nil {
			t.Errorf("reinstall args pk=%s gw4=%v gw6=%v", publicKey, got4, got6)
		}
		return nil
	}

	exitRoutesWinning = func(net.IP, net.IP) bool { return false }
	refreshHealthyExitRoutes(&igwStatus{isHealthy: true, publicKey: "peer", gw4: gw4})
	if pins != 1 || reinstalls != 1 {
		t.Fatalf("healthy with exit routes lost: pins=%d reinstalls=%d, want 1 and 1", pins, reinstalls)
	}

	refreshHealthyExitRoutes(&igwStatus{isHealthy: false, publicKey: "peer", gw4: gw4})
	if pins != 1 || reinstalls != 1 {
		t.Fatalf("unhealthy exit must keep the ISP default: pins=%d reinstalls=%d", pins, reinstalls)
	}

	exitRoutesWinning = func(net.IP, net.IP) bool { return true }
	refreshHealthyExitRoutes(&igwStatus{isHealthy: true, publicKey: "peer", gw4: gw4})
	if pins != 2 || reinstalls != 1 {
		t.Fatalf("healthy with exit routes winning: pins=%d reinstalls=%d, want 2 and 1", pins, reinstalls)
	}
}

func TestGatewayMoveClearsFailureStreak(t *testing.T) {
	prevPin, prevWin, prevGw := pinExitUnderlay, exitRoutesWinning, currentUnderlayGateway
	t.Cleanup(func() {
		pinExitUnderlay, exitRoutesWinning, currentUnderlayGateway = prevPin, prevWin, prevGw
	})
	pinExitUnderlay = func(string) {}
	exitRoutesWinning = func(net.IP, net.IP) bool { return true }

	calls := 0
	currentUnderlayGateway = func() string {
		calls++
		if calls == 1 {
			return "10.0.0.1,"
		}
		return "10.1.0.1,"
	}
	s := &igwStatus{isHealthy: true, publicKey: "peer", failureCount: 2}
	if !refreshHealthyExitRoutes(s) {
		t.Fatal("expected the LAN gateway move to be reported")
	}
	if s.failureCount != 0 {
		t.Fatalf("failureCount = %d after gateway move, want 0", s.failureCount)
	}

	calls = 0
	currentUnderlayGateway = func() string { return "10.1.0.1," }
	s.failureCount = 2
	if refreshHealthyExitRoutes(s) {
		t.Fatal("unchanged gateway reported as a move")
	}
	if s.failureCount != 2 {
		t.Fatalf("failureCount = %d with a stable gateway, want 2", s.failureCount)
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
