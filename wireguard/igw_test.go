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
