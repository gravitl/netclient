package wireguard

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStaleOverlayAddrs_ignoresLinkLocal(t *testing.T) {
	want := map[string]struct{}{"100.64.0.2": {}}
	live := []net.IP{
		net.ParseIP("100.64.0.2"),
		net.ParseIP("fe80::60ff:34ba:8df1:2202"),
	}
	assert.Empty(t, staleOverlayAddrs(live, want), "Darwin utun fe80:: must not count as stale")
}

func TestStaleOverlayAddrs_detectsLeftoverOverlay(t *testing.T) {
	want := map[string]struct{}{"100.64.0.2": {}}
	live := []net.IP{
		net.ParseIP("100.64.0.2"),
		net.ParseIP("100.64.1.9"),
		net.ParseIP("fe80::1"),
	}
	assert.Equal(t, []string{"100.64.1.9"}, staleOverlayAddrs(live, want))
}
