package turn

import (
	"net"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/nmproxy/config"
	peerpkg "github.com/gravitl/netclient/nmproxy/peer"
	"github.com/gravitl/netclient/nmproxy/wg"
	"github.com/gravitl/netmaker/logger"
	nm_models "github.com/gravitl/netmaker/models"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func WatchPeerSignals(peerKey string, peerSignalCh chan nm_models.Signal) {
	for signal := range peerSignalCh {
		// recieved new signal from peer, check if turn endpoint is different
		t, ok := config.GetCfg().GetTurnCfg(peerKey)
		if ok {
			if signal.TurnRelayEndpoint != "" && t.PeerTurnAddr != signal.TurnRelayEndpoint {
				config.GetCfg().UpdatePeerTurnAddr(peerKey, signal.TurnRelayEndpoint)
				// reset
				peerTurnEndpoint, err := net.ResolveUDPAddr("udp", signal.TurnRelayEndpoint)
				if err != nil {
					continue
				}
				if conn, ok := config.GetCfg().GetPeer(peerKey); ok {
					conn.Config.PeerEndpoint = peerTurnEndpoint
					config.GetCfg().UpdatePeer(&conn)
					conn.ResetConn()

				} else {
					// new connection
					peer, err := wg.GetPeer(ncutils.GetInterfaceName(), peerKey)
					if err == nil {
						peerpkg.AddNew(t.Server, wgtypes.PeerConfig{
							PublicKey:                   peer.PublicKey,
							PresharedKey:                &peer.PresharedKey,
							Endpoint:                    peer.Endpoint,
							PersistentKeepaliveInterval: &peer.PersistentKeepaliveInterval,
							AllowedIPs:                  peer.AllowedIPs,
						}, t.PeerConf, false, peerTurnEndpoint, true)
					}
				}

			}
			// signal back to peer
			// signal peer with the host relay addr for the peer
			if signal.Reply {
				continue
			}
			err := SignalPeer(t.Server, nm_models.Signal{
				FromHostPubKey:    config.GetCfg().GetDevicePubKey().String(),
				TurnRelayEndpoint: t.TurnConn.LocalAddr().String(),
				ToHostPubKey:      peerKey,
				Reply:             true,
			})
			if err != nil {
				logger.Log(0, "---> failed to signal peer: ", err.Error())
				continue
			}
		}
	}
}
