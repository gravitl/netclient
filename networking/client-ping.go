package networking

import (
	"fmt"
	"net"

	"github.com/gravitl/netclient/cache"
	"github.com/gravitl/netclient/metrics"
	"golang.org/x/exp/slog"
)

// FindBestEndpoint - requests against a given addr and port
func FindBestEndpoint(peerIp, peerPubKey string, port int) {

	connected, _ := metrics.PeerConnStatus(peerIp, port, 2)
	if connected {
		peerEndpoint, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", peerIp, port))
		if err != nil {
			slog.Error("failed to parse peer udp addr", "peeraddr", fmt.Sprintf("%s:%d", peerIp, port), "err", err.Error())
			return
		}
		storeNewPeerIface(peerPubKey, peerEndpoint)
	} else {
		if retryCnt, ok := cache.SkipEndpointCache.Load(peerPubKey); ok {
			cnt := retryCnt.(int)
			if cnt <= 3 {
				cnt += 1
				cache.SkipEndpointCache.Store(peerPubKey, cnt)
			}
		} else {
			cache.SkipEndpointCache.Store(peerPubKey, 1)
		}
	}
}
