package functions

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestScheduleAutoRelayPeerScan_coalescesRapidUpdates(t *testing.T) {
	prev := autoRelayWatchCtx.Load()
	prevGen := autoRelayScheduleGen.Load()
	t.Cleanup(func() {
		autoRelayWatchCtx.Store(prev)
		autoRelayScheduleGen.Store(prevGen)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	autoRelayWatchCtx.Store(&ctx)

	scheduleAutoRelayPeerScan()
	g1 := autoRelayScheduleGen.Load()
	scheduleAutoRelayPeerScan()
	g2 := autoRelayScheduleGen.Load()
	if g2 != g1+1 {
		t.Fatalf("expected schedule gen to advance, got %d after %d", g2, g1)
	}
	scheduleAutoRelayPeerScan()
	g3 := autoRelayScheduleGen.Load()
	if g3 != g2+1 {
		t.Fatalf("expected schedule gen to advance again, got %d after %d", g3, g2)
	}
	if shouldRunScheduledScan(g1, g3) {
		t.Fatal("stale schedule gen should not run")
	}
	if !shouldRunScheduledScan(g3, autoRelayScheduleGen.Load()) {
		t.Fatal("latest schedule gen should run")
	}
}

func TestScheduleAutoRelayPeerScan_noopWithoutWatcher(t *testing.T) {
	prev := autoRelayWatchCtx.Load()
	prevGen := autoRelayScheduleGen.Load()
	t.Cleanup(func() {
		autoRelayWatchCtx.Store(prev)
		autoRelayScheduleGen.Store(prevGen)
	})
	autoRelayWatchCtx.Store(nil)
	before := autoRelayScheduleGen.Load()
	scheduleAutoRelayPeerScan()
	if autoRelayScheduleGen.Load() != before {
		t.Fatal("schedule should no-op when watcher ctx is nil")
	}
}

func TestShouldRunScheduledScan_afterGraceGate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	var gen uint64 = 7
	current := gen
	go func(scheduled uint64) {
		timer := time.NewTimer(20 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if !shouldRunScheduledScan(scheduled, current) {
			return
		}
		close(done)
	}(gen)

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected scheduled scan gate to fire after grace")
	}
}

func TestPeerNeedsCachedEndpoint(t *testing.T) {
	addr := func(ip string, port int) *net.UDPAddr { return &net.UDPAddr{IP: net.ParseIP(ip), Port: port} }
	cached := addr("192.0.2.44", 51820)
	for _, tt := range []struct {
		name     string
		endpoint *net.UDPAddr
		want     bool
	}{
		{"peer without endpoint", nil, true},
		{"peer with another address", addr("198.51.100.9", 51820), true},
		{"peer with another port", addr("192.0.2.44", 51821), false},
		{"peer with the cached endpoint", cached, false},
	} {
		if got := peerNeedsCachedEndpoint(tt.endpoint, cached); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}
