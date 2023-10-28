package networking

import (
	"net"

	"github.com/gravitl/netclient/metrics"
)

// FindBestEndpoint - requests against a given addr and port
func FindBestEndpoint(peerIp, currentHostPubKey, peerPubKey string, port int) {

	connected, _ := metrics.PeerConnStatus(peerIp, port)
	if connected {
		storeNewPeerIface(peerPubKey, &net.UDPAddr{
			IP:   net.IP(peerIp),
			Port: port,
		})
	}
}
