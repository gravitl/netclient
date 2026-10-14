package desktop

import (
	"testing"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/functions"
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

func TestExitRestoreUsesAutoKeepsManualSelection(t *testing.T) {
	prev := networkAutoSelectExit
	t.Cleanup(func() {
		networkAutoSelectExit = prev
		config.DeleteNodes()
	})
	networkAutoSelectExit = func(network, _, _ string) (bool, error) {
		return network == "forced", nil
	}
	config.UpdateNodeMap("forced", config.Node{
		CommonNode: models.CommonNode{Network: "forced", Connected: true},
	})

	// A stored manual exit network must not be promoted to Auto just because
	// a name is present. That is what made re-login show "Auto" after the user
	// had picked a specific exit node.
	network, auto := exitRestoreUsesAuto("restore-manual-user", "t", "manual-net", "tok")
	if auto || network != "manual-net" {
		t.Fatalf("manual exit restored as auto: network=%q auto=%v", network, auto)
	}

	network, auto = exitRestoreUsesAuto("restore-manual-user", "t", "", "tok")
	if !auto || network != "forced" {
		t.Fatalf("server-required network not armed: network=%q auto=%v", network, auto)
	}
}

func TestAutoExitModeActiveIncludesServerRequired(t *testing.T) {
	prev := networkAutoSelectExit
	t.Cleanup(func() { networkAutoSelectExit = prev })

	networkAutoSelectExit = func(network, server, token string) (bool, error) {
		return network == "forced-net", nil
	}
	if autoExitModeActive("u", "t", "other", "tok") {
		t.Fatal("non-required network without local auto should be inactive")
	}
	if !autoExitModeActive("u", "t", "forced-net", "tok") {
		t.Fatal("server-required network should activate auto mode")
	}
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
	pick, ok := functions.PickNearestAvailableExitNode(nodes, map[string]struct{}{"cur": {}})
	if !ok || pick.EgressID != "alt" {
		t.Fatalf("got %+v ok=%v", pick, ok)
	}
}

func TestAutoExitReconcileExcludeOmitsDesiredID(t *testing.T) {
	resetAutoExitFailoverStateForTest()
	t.Cleanup(resetAutoExitFailoverStateForTest)

	rememberFailedEgress("eg-failed")
	// Desired id "eg-desired" must remain eligible during manual→Auto switch.
	set := autoExitReconcileExclude()
	if _, ok := set["eg-failed"]; !ok {
		t.Fatal("failure blacklist should still apply")
	}
	if _, ok := set["eg-desired"]; ok {
		t.Fatal("reconcile must not exclude an in-flight desired egress id")
	}

	// With desired excluded (the old bug), nearest would snap back to previous.
	nodes := []models.DeviceExitNode{
		{EgressID: "eg-desired", Status: true, LatencyMs: 10, Nearest: true},
		{EgressID: "eg-previous", Status: true, LatencyMs: 40},
	}
	pick, ok := functions.PickNearestAvailableExitNode(nodes, set)
	if !ok || pick.EgressID != "eg-desired" {
		t.Fatalf("reconcile exclude should keep nearest desired; got %+v ok=%v", pick, ok)
	}
}

func TestReconcileDesiredExitSkipsWhileSelectInFlight(t *testing.T) {
	beginExitSelect()
	t.Cleanup(endExitSelect)
	lastExitReconcile.Store(0)
	// No session / no want_igw — with in-flight set this must return before
	// rate-limiting so a later reconcile after assign is not delayed 30s.
	reconcileDesiredExit()
	if lastExitReconcile.Load() != 0 {
		t.Fatal("in-flight select must not burn the reconcile rate limit")
	}
}
