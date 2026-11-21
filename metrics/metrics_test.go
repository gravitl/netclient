package metrics

import (
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestRecentHandshakeFallback(t *testing.T) {
	for _, tt := range []struct {
		name   string
		rx, tx int64
		age    time.Duration
		want   bool
	}{
		{"handshake past the rekey time", 100, 100, 150 * time.Second, true},
		{"handshake past the reject time", 100, 100, 190 * time.Second, false},
		{"no received bytes", 0, 100, 10 * time.Second, false},
	} {
		peer := wgtypes.Peer{ReceiveBytes: tt.rx, TransmitBytes: tt.tx, LastHandshakeTime: time.Now().Add(-tt.age)}
		if got := recentHandshakeFallback(peer); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}
