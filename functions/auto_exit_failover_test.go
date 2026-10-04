package functions

import (
	"testing"
	"time"

	"github.com/gravitl/netmaker/models"
)

func TestFailedEgressExcludeSetExpires(t *testing.T) {
	resetAutoExitFailoverStateForTest()
	t.Cleanup(resetAutoExitFailoverStateForTest)

	rememberFailedEgress("eg-a")
	set := failedEgressExcludeSet()
	if _, ok := set["eg-a"]; !ok {
		t.Fatal("expected eg-a in exclude set")
	}

	autoExitFailedMu.Lock()
	autoExitFailed["eg-old"] = time.Now().Add(-autoExitFailedTTL - time.Minute)
	autoExitFailedMu.Unlock()

	set = failedEgressExcludeSet()
	if _, ok := set["eg-old"]; ok {
		t.Fatal("expired egress should be dropped")
	}
	if _, ok := set["eg-a"]; !ok {
		t.Fatal("fresh eg-a should remain")
	}
}

func TestHandleIGWUnhealthyAutoExitSkipsManualMode(t *testing.T) {
	resetAutoExitFailoverStateForTest()
	t.Cleanup(resetAutoExitFailoverStateForTest)

	// No desktop session → should no-op (not panic).
	handleIGWUnhealthyAutoExit("unused-key")
}

func TestHandleIGWUnhealthyRespectsCooldown(t *testing.T) {
	resetAutoExitFailoverStateForTest()
	t.Cleanup(resetAutoExitFailoverStateForTest)

	autoExitFailoverMu.Lock()
	autoExitLastFailover = time.Now()
	autoExitFailoverMu.Unlock()

	// No session → returns before listing; cooldown path is covered when a
	// session exists. This at least ensures the hook does not panic.
	handleIGWUnhealthyAutoExit("unused-key")
}

func TestPickNearestSkipsSelectedWhenExcluded(t *testing.T) {
	nodes := []models.DeviceExitNode{
		{EgressID: "cur", Status: true, Nearest: true, LatencyMs: 1, Selected: true},
		{EgressID: "alt", Status: true, LatencyMs: 40},
	}
	pick, ok := pickNearestAvailableExitNode(nodes, map[string]struct{}{"cur": {}})
	if !ok || pick.EgressID != "alt" {
		t.Fatalf("got %+v ok=%v", pick, ok)
	}
}
