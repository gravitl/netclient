package metrics

import (
	"time"

	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/wg"
)

const MetricCollectionInterval = time.Second * 25

// PeerConnectionStatus - get peer connection status from wireguard interface
func PeerConnectionStatus(peerPublicKey string) bool {
	ifacePeers, err := wg.GetPeers(config.GetCfg().GetIface().Name)
	if err != nil {
		return false
	}
	for _, peer := range ifacePeers {
		if peer.PublicKey.String() == peerPublicKey {
			return peer.LastHandshakeTime.After(time.Now().Add(-3*time.Minute)) && peer.ReceiveBytes+peer.TransmitBytes > 0
		}
	}
	return false
}
