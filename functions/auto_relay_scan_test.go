package functions

import (
	"context"
	"testing"
	"time"
)

func TestScheduleAutoRelayPeerScan_coalescesRapidUpdates(t *testing.T) {
	prevCtx := autoRelayWatchCtx
	prevGen := autoRelayScheduleGen.Load()
	t.Cleanup(func() {
		autoRelayWatchCtx = prevCtx
		autoRelayScheduleGen.Store(prevGen)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	autoRelayWatchCtx = ctx

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
	prevCtx := autoRelayWatchCtx
	prevGen := autoRelayScheduleGen.Load()
	t.Cleanup(func() {
		autoRelayWatchCtx = prevCtx
		autoRelayScheduleGen.Store(prevGen)
	})
	autoRelayWatchCtx = nil
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
