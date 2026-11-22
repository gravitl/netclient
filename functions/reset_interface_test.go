package functions

// notifyEgressReset sends on wireguard.EgressResetCh, whose only reader is the egress HA failover loop, which runs for Pro servers only. The channel buffers two values, so a notify on a full channel must return instead of blocking.

import (
	"testing"
	"time"

	"github.com/gravitl/netclient/wireguard"
)

func TestNotifyEgressResetReturnsWithFullEgressResetCh(t *testing.T) {
	drainEgressResetCh()
	t.Cleanup(drainEgressResetCh)
	for i := 0; i < cap(wireguard.EgressResetCh); i++ {
		wireguard.EgressResetCh <- struct{}{}
	}
	for i := 0; i < 3; i++ {
		done := make(chan struct{})
		go func() {
			notifyEgressReset()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("notifyEgressReset call %d blocked on a full EgressResetCh", i+1)
		}
	}
	if got, want := len(wireguard.EgressResetCh), cap(wireguard.EgressResetCh); got != want {
		t.Fatalf("EgressResetCh holds %d values after three notifies, want %d", got, want)
	}
}

func drainEgressResetCh() {
	for {
		select {
		case <-wireguard.EgressResetCh:
		default:
			return
		}
	}
}
