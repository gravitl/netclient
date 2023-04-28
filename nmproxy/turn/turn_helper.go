package turn

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/models"
	peerpkg "github.com/gravitl/netclient/nmproxy/peer"
	wireguard "github.com/gravitl/netclient/nmproxy/wg"
	"github.com/gravitl/netmaker/logger"
	nm_models "github.com/gravitl/netmaker/models"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PeerSignalCh - channel to recieve peer signals
var PeerSignalCh = make(chan nm_models.Signal, 50)

// WatchPeerSignals - processes the peer signals for any turn updates from peers
func WatchPeerSignals(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	defer logger.Log(0, "Exiting Peer Signals Watcher...")
	for {
		select {
		case <-ctx.Done():
			return
		case signal := <-PeerSignalCh:
			// recieved new signal from peer, check if turn endpoint is different
			peerTurnEndpoint, err := net.ResolveUDPAddr("udp", signal.TurnRelayEndpoint)
			if err != nil {
				continue
			}

			t, ok := config.GetCfg().GetPeerTurnCfg(signal.Server, signal.FromHostPubKey)
			if ok {
				if signal.TurnRelayEndpoint == "" {
					continue
				}
				// reset
				if conn, ok := config.GetCfg().GetPeer(signal.FromHostPubKey); ok {
					if conn.Config.UsingTurn && t.PeerTurnAddr != signal.TurnRelayEndpoint {
						logger.Log(0, fmt.Sprintf("Turn Peer Addr Has Been Changed From %s to %s", t.PeerTurnAddr, signal.TurnRelayEndpoint))
						config.GetCfg().UpdatePeerTurnAddr(signal.Server, signal.FromHostPubKey, signal.TurnRelayEndpoint)
						conn.Config.PeerEndpoint = peerTurnEndpoint
						config.GetCfg().UpdatePeer(&conn)
						config.GetCfg().ResetPeer(signal.FromHostPubKey)
					}

				} else {
					// new connection
					config.GetCfg().SetPeerTurnCfg(signal.Server, signal.FromHostPubKey, models.TurnPeerCfg{
						Server:       signal.Server,
						PeerConf:     t.PeerConf,
						PeerTurnAddr: signal.TurnRelayEndpoint,
					})

					peer, err := wireguard.GetPeer(ncutils.GetInterfaceName(), signal.FromHostPubKey)
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

				// if respone to the signal you sent,then don't signal back
				if signal.Reply {
					continue
				}
				// signal back to peer
				// signal peer with the host relay addr for the peer
				if hostTurnCfg, ok := config.GetCfg().GetTurnCfg(signal.Server); ok && hostTurnCfg.TurnConn != nil {
					hostTurnCfg.Mutex.RLock()
					err := SignalPeer(signal.Server, nm_models.Signal{
						Server:            signal.Server,
						FromHostPubKey:    signal.ToHostPubKey,
						TurnRelayEndpoint: hostTurnCfg.TurnConn.LocalAddr().String(),
						ToHostPubKey:      signal.FromHostPubKey,
						Reply:             true,
					})
					hostTurnCfg.Mutex.RUnlock()
					if err != nil {
						logger.Log(0, "failed to signal peer: ", err.Error())
						continue
					}
				}

			}
		}
	}
}

// ShouldUseTurn - checks the nat type to check if peer needs to use turn for communication
func ShouldUseTurn(natType string) bool {
	// if behind  DOUBLE or ASYM Nat type, use turn to reach peer
	if natType == nm_models.NAT_Types.Asymmetric || natType == nm_models.NAT_Types.Double {
		return true
	}
	return false
}
