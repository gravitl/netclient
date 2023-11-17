package turn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/auth"
	ncconfig "github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/metrics"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/models"
	peerpkg "github.com/gravitl/netclient/nmproxy/peer"
	"github.com/gravitl/netclient/nmproxy/wg"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	nm_models "github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	// PeerSignalCh - channel to recieve peer signals
	PeerSignalCh = make(chan nm_models.Signal, 50)
	// peerConnectionCheckInterval - time interval to check peer connection status
	peerConnectionCheckInterval = time.Second * 25
	// LastHandShakeThreshold - threshold for considering inactive connection
	LastHandShakeThreshold = time.Minute * 3

	ResetCh = make(chan struct{}, 2)
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
			// if signal is older than 10s ignore it,wait for a fresh signal from peer
			if time.Now().Unix()-signal.TimeStamp > 5 {
				continue
			}
			switch signal.Action {
			case nm_models.ConnNegotiation:
				if signal.IsPro {
					handlePeerFailOver(signal)
					continue
				}
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

func handlePeerFailOver(signal nm_models.Signal) error {
	if !signal.Reply {
		// signal back
		fmt.Println("REPLYING RECIV SIGNAL FROM: ", signal.FromHostPubKey)
		err := SignalPeer(signal.Server, nm_models.Signal{
			Server:         signal.Server,
			FromHostID:     signal.ToHostID,
			FromNodeID:     signal.ToNodeID,
			FromHostPubKey: signal.ToHostPubKey,
			ToHostPubKey:   signal.FromHostPubKey,
			ToHostID:       signal.FromHostID,
			ToNodeID:       signal.FromNodeID,
			Reply:          true,
			Action:         nm_models.ConnNegotiation,
		})
		if err != nil {
			slog.Error("failed to signal peer", "error", err.Error())
		}
	}

	if ncconfig.Netclient().NatType == nm_models.NAT_Types.BehindNAT {
		err := failOverMe(signal.Server, signal.ToNodeID, signal.FromNodeID)
		if err != nil {
			slog.Error("failed to signal server to relay me", "error", err)
		}
	}
	return nil
}

func handlePeerNegotiation(signal nm_models.Signal) error {
	peerTurnEndpoint, err := net.ResolveUDPAddr("udp", signal.TurnRelayEndpoint)
	if err != nil {
		return err
	}
	t, ok := config.GetCfg().GetPeerTurnCfg(signal.FromHostPubKey)
	if ok {
		if signal.TurnRelayEndpoint == "" {
			return errors.New("peer turn endpoint is nil")
		}
		// reset
		if conn, ok := config.GetCfg().GetPeer(signal.FromHostPubKey); ok {
			if t.PeerTurnAddr != signal.TurnRelayEndpoint {
				logger.Log(0, fmt.Sprintf("Turn Peer Addr Has Been Changed From %s to %s", t.PeerTurnAddr, signal.TurnRelayEndpoint))
				config.GetCfg().UpdatePeerTurnAddr(signal.FromHostPubKey, signal.TurnRelayEndpoint)
				conn.Config.PeerEndpoint = peerTurnEndpoint
				config.GetCfg().UpdatePeer(&conn)
				config.GetCfg().ResetPeer(signal.FromHostPubKey)
			} else if !signal.Reply {
				// reset conn
				connected, err := isPeerConnected(signal.FromHostPubKey)
				if err != nil {
					slog.Info("failed to check if peer is connected: ", err.Error())
				}
				if !connected {
					config.GetCfg().ResetPeer(signal.FromHostPubKey)
				}

			}

		} else {
			// new connection
			config.GetCfg().SetPeerTurnCfg(signal.FromHostPubKey, models.TurnPeerCfg{
				Server:       signal.Server,
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
				}, peerTurnEndpoint)
			}

		}

		// if response to the signal you sent,then don't signal back
		if signal.Reply {
			return nil
		}
		// signal back to peer
		// signal peer with the host relay addr for the peer
		if hostTurnCfg := config.GetCfg().GetTurnCfg(); hostTurnCfg != nil && hostTurnCfg.TurnConn != nil {
			hostTurnCfg.Mutex.RLock()
			err := SignalPeer(signal.Server, nm_models.Signal{
				Server:            signal.Server,
				FromHostPubKey:    signal.ToHostPubKey,
				FromHostID:        signal.ToHostID,
				TurnRelayEndpoint: hostTurnCfg.TurnConn.LocalAddr().String(),
				ToHostPubKey:      signal.FromHostPubKey,
				ToHostID:          signal.FromHostID,
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
		config.GetCfg().DeletePeerTurnCfg(signal.FromHostPubKey)
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
	t := time.NewTicker(peerConnectionCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ResetCh:
			if t != nil {
				t.Reset(peerConnectionCheckInterval)
			}
		case <-t.C:
			// if peersAreConnected() {
			// 	continue
			// }
			fmt.Println("----->0 SENDING SIGNAL TO PEERRR: ")
			iface, err := wg.GetWgIface(ncutils.GetInterfaceName())
			if err != nil {
				logger.Log(1, "failed to get iface: ", err.Error())
				continue
			}
			nodes := ncconfig.GetNodes()
			if len(nodes) == 0 {
				continue
			}
			for _, node := range nodes {
				if node.Server != ncconfig.CurrServer {
					continue
				}
				fmt.Println("-----> -1 SENDING SIGNAL TO PEERRR: ")
				peers, err := getPeerInfo(node)
				if err != nil {
					slog.Error("failed to get peer Info", "error", err)
					continue
				}
				fmt.Println("-----> -2 SENDING SIGNAL TO PEERRR: ", len(peers))
				for pubKey, peer := range peers {
					if peer.IsExtClient {
						continue
					}
					fmt.Println("----->1 SENDING SIGNAL TO PEERRR: ", pubKey)
					connected, _ := metrics.PeerConnStatus(peer.Address, peer.ListenPort)
					if connected && pubKey != "b6E+SCOhR51ZOxxRdTkX03N1XGkx2liqrk5BOs5b03o=" {
						// peer is connected,so continue
						continue
					}
					fmt.Println("----->2 SENDING SIGNAL TO PEERRR: ", pubKey)
					s := nm_models.Signal{
						Server:         ncconfig.CurrServer,
						FromHostID:     ncconfig.Netclient().ID.String(),
						ToHostID:       peer.HostID,
						FromNodeID:     node.ID.String(),
						ToNodeID:       peer.ID,
						FromHostPubKey: iface.Device.PublicKey.String(),
						ToHostPubKey:   pubKey,
						Action:         nm_models.ConnNegotiation,
						TimeStamp:      time.Now().Unix(),
					}
					server := ncconfig.GetServer(ncconfig.CurrServer)
					if server == nil {
						continue
					}
					if !server.IsPro {
						turnCfg := config.GetCfg().GetTurnCfg()
						if turnCfg == nil || turnCfg.TurnConn == nil {
							continue
						}
						if _, ok := config.GetCfg().GetPeerTurnCfg(pubKey); !ok {
							config.GetCfg().SetPeerTurnCfg(pubKey, models.TurnPeerCfg{})
						}
						turnCfg.Mutex.RLock()
						s.TurnRelayEndpoint = turnCfg.TurnConn.LocalAddr().String()
						turnCfg.Mutex.RUnlock()
					}
					// signal peer
					err = SignalPeer(ncconfig.CurrServer, s)
					if err != nil {
						logger.Log(2, "failed to signal peer: ", err.Error())
					}

				}
			}

		}
	}
}

func peersAreConnected() bool {
	peers := ncconfig.Netclient().HostPeers
	for _, peer := range peers {
		if connected, _ := isPeerConnected(peer.PublicKey.String()); !connected {
			return false
		}
	}
	return true
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

// DissolvePeerConnections - notifies all peers to disconnect from using turn.
func DissolvePeerConnections() {
	logger.Log(0, "Dissolving TURN Peer Connections...")
	port := ncconfig.Netclient().WgPublicListenPort
	if port == 0 {
		port = ncconfig.Netclient().ListenPort
	}

	turnPeers := config.GetCfg().GetAllTurnPeersCfg()
	for peerPubKey := range turnPeers {
		err := SignalPeer(ncconfig.CurrServer, nm_models.Signal{
			FromHostPubKey:    ncconfig.Netclient().PublicKey.String(),
			ToHostPubKey:      peerPubKey,
			TurnRelayEndpoint: fmt.Sprintf("%s:%d", ncconfig.Netclient().EndpointIP.String(), port),
			Action:            nm_models.Disconnect,
		})
		if err != nil {
			logger.Log(0, "failed to signal peer: ", peerPubKey, err.Error())
		}
	}

}

func getPeerInfo(node ncconfig.Node) (nm_models.PeerMap, error) {
	server := ncconfig.GetServer(node.Server)
	if server == nil {
		return nil, errors.New("server is nil")
	}
	token, err := auth.Authenticate(server, ncconfig.Netclient())
	if err != nil {
		logger.Log(1, "failed to authenticate when publishing metrics", err.Error())
		return nil, err
	}
	url := fmt.Sprintf("https://%s/api/nodes/%s/%s", server.API, node.Network, node.ID)
	endpoint := httpclient.JSONEndpoint[nm_models.NodeGet, nm_models.ErrorResponse]{
		URL:           url,
		Method:        http.MethodGet,
		Authorization: "Bearer " + token,
		Data:          nil,
		Response:      nm_models.NodeGet{},
		ErrorResponse: nm_models.ErrorResponse{},
	}
	response, errData, err := endpoint.GetJSON(nm_models.NodeGet{}, nm_models.ErrorResponse{})
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			logger.Log(0, "status error calling ", endpoint.URL, errData.Message)
			return nil, err
		}
		logger.Log(1, "failed to read from server during metrics publish", err.Error())
		return nil, err
	}

	return response.PeerIDs, nil
}
