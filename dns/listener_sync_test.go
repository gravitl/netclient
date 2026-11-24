package dns

import (
	"runtime"
	"testing"
)

func TestStartListenersAlreadyUpStillReturnsTrue(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("darwin binds a single loopback listener")
	}
	inst := GetDNSServerInstance()
	t.Cleanup(func() {
		inst.StopListeners()
	})
	// Simulate listeners already bound for network A. StartListeners must not
	// early-return before considering other connected networks (additive path).
	inst.AddrStr = "10.0.0.1:53"
	inst.AddrList = []string{"10.0.0.1:53"}

	alreadyUp := inst.StartListeners()
	if !alreadyUp {
		t.Fatal("expected alreadyUp when AddrStr is set")
	}
	if got := inst.ListenerAddr(); got == "" {
		t.Fatal("existing listener address should remain")
	}
}
