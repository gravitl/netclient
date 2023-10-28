package networking

import (
	"fmt"
	"net"

	"github.com/gravitl/netclient/metrics"
	"golang.org/x/exp/slog"
)

// FindBestEndpoint - requests against a given addr and port
func FindBestEndpoint(peerIp, peerPubKey string, port int) {

	connected, _ := metrics.PeerConnStatus(peerIp, port)
	if connected {
		fmt.Println("---------> ##### Storing Priv IP: ", peerIp, port, " PeerPubKey: ", peerPubKey)
		peerEndpoint, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", peerIp, port))
		if err != nil {
			slog.Error("failed to parse peer udp addr", "peeraddr", fmt.Sprintf("%s:%d", peerIp, port), "err", err.Error())
			return
		}
		storeNewPeerIface(peerPubKey, peerEndpoint)
	}
}
