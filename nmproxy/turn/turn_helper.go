package turn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	ncconfig "github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/models"
	peerpkg "github.com/gravitl/netclient/nmproxy/peer"
	"github.com/gravitl/netclient/nmproxy/wg"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	nm_models "github.com/gravitl/netmaker/models"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	// PeerSignalCh - channel to recieve peer signals
	PeerSignalCh = make(chan nm_models.Signal, 50)
	// PeerConnectionCheckInterval - time interval to check peer connection status
	PeerConnectionCheckInterval = time.Minute
	// LastHandShakeThreshold - threshold for considering inactive connection
	LastHandShakeThreshold = time.Minute * 3
)

// WatchPeerSignals - processes the peer signals for any turn updates from peers
func WatchPeerSignals(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	defer logger.Log(0, "Exiting Peer Signals Watcher...")
	var err error
	for {
		select {
		case <-ctx.Done():
			return
		case signal := <-PeerSignalCh:
			// process recieved new signal from peer
			switch signal.Action {
			case nm_models.ConnNegotiation:
				err = handlePeerNegotiation(signal)
			case nm_models.Disconnect:
				err = handleDisconnect(signal)
			}
			if err != nil {
				logger.Log(2, fmt.Sprintf("Failed to perform action [%s]: %+v, Err: %v", signal.Action, signal.FromHostPubKey, err.Error()))
			}

		}
	}
}

func handlePeerNegotiation(signal nm_models.Signal) error {
	peerTurnEndpoint, err := net.ResolveUDPAddr("udp", signal.TurnRelayEndpoint)
	if err != nil {
		return err
	}
	t, ok := config.GetCfg().GetPeerTurnCfg(signal.Server, signal.FromHostPubKey)
	if ok {
		if signal.TurnRelayEndpoint == "" {
			return errors.New("peer turn endpoint is nil")
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

		// if response to the signal you sent,then don't signal back
		if signal.Reply {
			return nil
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
				Action:            nm_models.ConnNegotiation,
			})
			hostTurnCfg.Mutex.RUnlock()
			if err != nil {
				logger.Log(0, "failed to signal peer: ", err.Error())
				return err
			}
		}

	}
	return nil
}

func handleDisconnect(signal nm_models.Signal) error {

	if signal.TurnRelayEndpoint == "" {
		return errors.New("peer endpoint is nil")
	}
	// this is the actual endpoint of peer sent to connect directly
	peerEndpoint, err := net.ResolveUDPAddr("udp", signal.TurnRelayEndpoint)
	if err != nil {
		return err
	}
	if _, ok := config.GetCfg().GetPeer(signal.FromHostPubKey); ok {
		logger.Log(0, "Resetting Peer Conn to talk directly: ", peerEndpoint.String())
		config.GetCfg().DeletePeerTurnCfg(signal.Server, signal.FromHostPubKey)
		config.GetCfg().RemovePeer(signal.FromHostPubKey)
	}
	pubKey, err := wgtypes.ParseKey(signal.FromHostPubKey)
	if err != nil {
		return err
	}
	return wireguard.UpdatePeer(&wgtypes.PeerConfig{
		PublicKey:  pubKey,
		Endpoint:   peerEndpoint,
		UpdateOnly: true,
	})
}

// WatchPeerConnections - periodically watches peer connections.
// if connection is bad, host will signal peers to use turn
func WatchPeerConnections(ctx context.Context, waitg *sync.WaitGroup) {
	defer waitg.Done()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			iface, err := wg.GetWgIface(ncutils.GetInterfaceName())
			if err != nil {
				logger.Log(1, "failed to get iface: ", err.Error())
				continue
			}
			peers := ncconfig.Netclient().HostPeers
			for _, peer := range peers {

				if peer.Endpoint == nil {
					continue
				}
				connected, err := isPeerConnected(peer.PublicKey.String())
				if err != nil {
					logger.Log(0, "failed to check if peer is connected: ", err.Error())
					continue
				}
				if connected {
					// peer is connected,so continue
					continue
				}
				// signal peer to use turn
				turnCfg, ok := config.GetCfg().GetTurnCfg(ncconfig.CurrServer)
				if !ok || turnCfg.TurnConn == nil {
					continue
				}
				if _, ok := config.GetCfg().GetPeerTurnCfg(ncconfig.CurrServer, peer.PublicKey.String()); !ok {
					config.GetCfg().SetPeerTurnCfg(ncconfig.CurrServer, peer.PublicKey.String(), models.TurnPeerCfg{
						Server:   ncconfig.CurrServer,
						PeerConf: nm_models.PeerConf{},
					})
				}
				turnCfg.Mutex.RLock()
				// signal peer with the host relay addr for the peer
				err = SignalPeer(ncconfig.CurrServer, nm_models.Signal{
					Server:            ncconfig.CurrServer,
					FromHostPubKey:    iface.Device.PublicKey.String(),
					TurnRelayEndpoint: turnCfg.TurnConn.LocalAddr().String(),
					ToHostPubKey:      peer.PublicKey.String(),
					Action:            nm_models.ConnNegotiation,
				})
				turnCfg.Mutex.RUnlock()
				if err != nil {
					logger.Log(2, "failed to signal peer: ", err.Error())
				}

			}
		}
	}
}

// isPeerConnected - get peer connection status by checking last handshake time
func isPeerConnected(peerKey string) (connected bool, err error) {
	peer, err := wg.GetPeer(ncutils.GetInterfaceName(), peerKey)
	if err != nil {
		return
	}
	if !peer.LastHandshakeTime.IsZero() && !(time.Since(peer.LastHandshakeTime) > LastHandShakeThreshold) {
		connected = true
	}
	return
}

// ShouldUseTurn - checks the nat type to check if peer needs to use turn for communication
func ShouldUseTurn(natType string) bool {
	// if behind  DOUBLE or ASYM Nat type, use turn to reach peer
	if natType == nm_models.NAT_Types.Asymmetric || natType == nm_models.NAT_Types.Double {
		return true
	}
	return false
}

// DissolvePeerConnections - notifies all peers to disconnect from using turn.
func DissolvePeerConnections() {
	logger.Log(0, "Dissolving TURN Peer Connections...")
	port := ncconfig.Netclient().WgPublicListenPort
	if port == 0 {
		port = ncconfig.Netclient().ListenPort
	}
	turnPeers := config.GetCfg().GetAllTurnPeersCfg(ncconfig.CurrServer)
	for peerPubKey := range turnPeers {
		err := SignalPeer(ncconfig.CurrServer, nm_models.Signal{
			FromHostPubKey:    ncconfig.Netclient().PublicKey.String(),
			ToHostPubKey:      peerPubKey,
			TurnRelayEndpoint: fmt.Sprintf("%s:%d", ncconfig.Netclient().PublicKey.String(), port),
			Action:            nm_models.Disconnect,
		})
		if err != nil {
			logger.Log(0, "failed to signal peer: ", peerPubKey, err.Error())
		}
	}

}
