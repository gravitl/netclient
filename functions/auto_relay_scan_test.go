package functions

import (
	"context"
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

func TestIsAutoRelayPairWriter(t *testing.T) {
	low, high := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	if !isAutoRelayPairWriter(low, high) {
		t.Fatal("lower ID should be writer")
	}
	if isAutoRelayPairWriter(high, low) {
		t.Fatal("higher ID should not be writer")
	}
	if !isAutoRelayPairWriter(low, low) {
		t.Fatal("equal IDs should allow a single writer")
	}
}

func TestPeerSignalCooldownSurvivesWithoutClear(t *testing.T) {
	hostID := "cooldown-host"
	signalThrottleCache.Delete(hostID)
	t.Cleanup(func() { signalThrottleCache.Delete(hostID) })

	if peerSignalOnCooldown(hostID) {
		t.Fatal("expected no cooldown before mark")
	}
	markPeerSignalCooldown(hostID)
	if !peerSignalOnCooldown(hostID) {
		t.Fatal("expected cooldown after mark")
	}
	// Survives without an explicit Delete (reply path used to clear).
	if !peerSignalOnCooldown(hostID) {
		t.Fatal("cooldown should still be active")
	}
	signalThrottleCache.Delete(hostID)
	if peerSignalOnCooldown(hostID) {
		t.Fatal("expected cooldown cleared after unrelay-style Delete")
	}
}
