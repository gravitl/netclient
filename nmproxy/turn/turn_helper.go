package turn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/go-ping/ping"
	ncconfig "github.com/gravitl/netclient/config"
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
	var err error
	for {
		select {
		case <-ctx.Done():
			return
		case signal := <-PeerSignalCh:
			// process recieved new signal from peer
			switch signal.Action {
			case nm_models.ConnNegotitation:
				err = handlePeerNegotiaton(signal)
			case nm_models.DissolveConn:
				err = handleDissolveConn(signal)
			}
			if err != nil {
				logger.Log(0, fmt.Sprintf("Failed to perform action [%s]: %+v, Err: %v", signal.Action, signal.FromHostPubKey, err.Error()))
			}

		}
	}
}

func handlePeerNegotiaton(signal nm_models.Signal) error {
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

func handleDissolveConn(signal nm_models.Signal) error {

	if signal.TurnRelayEndpoint == "" {
		return errors.New("peer endpoint is nil")
	}
	// this is the actual endpoint of peer sent to connect directly
	peerEndpoint, err := net.ResolveUDPAddr("udp", signal.TurnRelayEndpoint)
	if err != nil {
		return err
	}
	if conn, ok := config.GetCfg().GetPeer(signal.FromHostPubKey); ok {
		logger.Log(0, "Resetting Peer Conn to talk directly: ", peerEndpoint.String())
		config.GetCfg().UpdatePeerTurnAddr(signal.Server, signal.FromHostPubKey, signal.TurnRelayEndpoint)
		conn.Config.PeerEndpoint = peerEndpoint
		config.GetCfg().UpdatePeer(&conn)
		config.GetCfg().ResetPeer(signal.FromHostPubKey)
	}
	return nil
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
			logger.Log(0, "Checking CONNECTIONS....")
			serverPeers := ncconfig.Netclient().HostPeers
			for server, peers := range serverPeers {
				for _, peerI := range peers {
					if len(peerI.AllowedIPs) > 0 && peerI.AllowedIPs[0].IP != nil {
						if !IsPeerConnected(peerI.AllowedIPs[0].IP.String()) {
							// signal peer to use turn
							turnCfg, ok := config.GetCfg().GetTurnCfg(server)
							if !ok {
								continue
							}
							if turnCfg.TurnConn != nil {
								if _, ok := config.GetCfg().GetPeerTurnCfg(server, peerI.PublicKey.String()); !ok {
									config.GetCfg().SetPeerTurnCfg(server, peerI.PublicKey.String(), models.TurnPeerCfg{
										Server:   server,
										PeerConf: nm_models.PeerConf{},
									})
								}
								// signal peer with the host relay addr for the peer
								err := SignalPeer(server, nm_models.Signal{
									Server:            server,
									FromHostPubKey:    config.GetCfg().GetDevicePubKey().String(),
									TurnRelayEndpoint: turnCfg.TurnConn.LocalAddr().String(),
									ToHostPubKey:      peerI.PublicKey.String(),
								})
								if err != nil {
									logger.Log(0, "---> failed to signal peer: ", err.Error())
								}
							}
						}
					}
				}

			}
		}

	}
}

// IsPeerConnected - get peer connection status by pinging
func IsPeerConnected(address string) (connected bool) {
	pinger, err := ping.NewPinger(address)
	if err != nil {
		logger.Log(0, "could not initiliaze ping peer address", address, err.Error())
		connected = false
	} else {
		pinger.Timeout = time.Second * 3
		err = pinger.Run()
		if err != nil {
			logger.Log(0, "failed to ping on peer address", address, err.Error())
			return false
		} else {
			pingStats := pinger.Statistics()
			if pingStats.PacketsRecv > 0 {
				connected = true
			}
		}
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

// DissolvePeerConnections - notifies all peers to disconnect from using turn to reach me.
func DissolvePeerConnections() {
	for _, server := range ncconfig.GetServers() {
		turnPeers := config.GetCfg().GetAllTurnPeersCfg(server)
		for peerPubKey := range turnPeers {
			go SignalPeer(server, nm_models.Signal{
				FromHostPubKey:    config.GetCfg().GetDevicePubKey().String(),
				ToHostPubKey:      peerPubKey,
				TurnRelayEndpoint: config.GetCfg().GetHostInfo().PublicIp.String(),
				Action:            nm_models.DissolveConn,
			})
		}
	}
}
