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

var PeerSignalCh = make(chan nm_models.Signal, 100)

func WatchPeerSignals() {

	for {
		select {
		// case <-ctx.Done():
		// 	return
		case signal := <-PeerSignalCh:
			// recieved new signal from peer, check if turn endpoint is different
			t, ok := config.GetCfg().GetPeerTurnCfg(signal.FromHostPubKey)
			if ok {
				if signal.TurnRelayEndpoint != "" && t.PeerTurnAddr != signal.TurnRelayEndpoint {
					config.GetCfg().UpdatePeerTurnAddr(signal.FromHostPubKey, signal.TurnRelayEndpoint)
					// reset
					peerTurnEndpoint, err := net.ResolveUDPAddr("udp", signal.TurnRelayEndpoint)
					if err != nil {
						continue
					}
					if conn, ok := config.GetCfg().GetPeer(signal.FromHostPubKey); ok {
						conn.Config.PeerEndpoint = peerTurnEndpoint
						config.GetCfg().UpdatePeer(&conn)
						conn.ResetConn()

					}

				}
				// signal back to peer
				// signal peer with the host relay addr for the peer
				if signal.Reply {
					continue
				}
				err := SignalPeer(t.Server, nm_models.Signal{
					FromHostPubKey:    signal.ToHostPubKey,
					TurnRelayEndpoint: config.GetCfg().GetTurnCfg().TurnConn.LocalAddr().String(),
					ToHostPubKey:      signal.FromHostPubKey,
					Reply:             true,
				})
				if err != nil {
					logger.Log(0, "---> failed to signal peer: ", err.Error())
					continue
				}
			} else {
				// new connection
				peerTurnEndpoint, err := net.ResolveUDPAddr("udp", signal.TurnRelayEndpoint)
				if err != nil {
					continue
				}
				peer, err := wg.GetPeer(ncutils.GetInterfaceName(), signal.FromHostPubKey)
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
	}
}

func ShouldUseTurn(natType string) bool {
	// if behind  DOUBLE or ASYM Nat type, allocate turn address for the host
	return true
	if natType == nm_models.NAT_Types.Asymmetric || natType == nm_models.NAT_Types.Double {
		return true
	}
	return false
}
