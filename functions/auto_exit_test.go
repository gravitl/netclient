package functions

import (
	"testing"

	"github.com/gravitl/netmaker/models"
)

func TestApplyEnforcedAutoExit(t *testing.T) {
	prevCheck := networkAutoSelectExit
	prevSelect := selectNearestExitNode
	t.Cleanup(func() {
		networkAutoSelectExit = prevCheck
		selectNearestExitNode = prevSelect
		autoExitEnforced.Delete("net")
	})

	var calls int
	networkAutoSelectExit = func(network, _, token string) (bool, error) {
		if token != "tok" {
			t.Fatalf("token %q", token)
		}
		return network == "net", nil
	}
	selectNearestExitNode = func(network, token string) (*models.DeviceExitNode, error) {
		calls++
		if network != "net" || token != "tok" {
			t.Fatalf("select %s %s", network, token)
		}
		return &models.DeviceExitNode{EgressID: "eg-near"}, nil
	}

	if err := applyEnforcedAutoExit("net", "tok"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("expected nearest select before connect, calls=%d", calls)
	}

	networkAutoSelectExit = func(string, string, string) (bool, error) { return false, nil }
	if err := applyEnforcedAutoExit("other", "tok"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("flag off must not select an exit")
	}
	if err := applyEnforcedAutoExit("net", ""); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("missing token must not select an exit")
	}
}
