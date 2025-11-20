package networking

import (
	"net"
	"time"

	"github.com/gravitl/netclient/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// IpBelongsToInterface - function to check if an IP belongs to any network interface
func IpBelongsToInterface(ip net.IP) bool {

	for _, iface := range config.Netclient().Interfaces {
		if iface.Address.Contains(ip) {
			return true
		}
	}
	return false
}

// isPeerConnected - get peer connection status by checking last handshake time
func IsPeerConnected(peer wgtypes.Peer) (connected bool, err error) {
	if !peer.LastHandshakeTime.IsZero() && !(time.Since(peer.LastHandshakeTime) > LastHandShakeThreshold) {
		connected = true
	}
	return
}
