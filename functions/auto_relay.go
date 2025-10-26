package functions

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/devilcove/httpclient"
	"github.com/google/uuid"
	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/metrics"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/networking"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

var (
	autoRelayCacheMutex = &sync.Mutex{}
	currentNodesCache   = make(map[string]models.Node)
	autoRelayCache      = make(map[models.NetworkID][]models.Node)
	gwNodesCache        = make(map[models.NetworkID][]models.Node)
	autoRelayConnTicker *time.Ticker
	signalThrottleCache = sync.Map{}
)

func getAutoRelayNodes(network models.NetworkID) []models.Node {
	autoRelayCacheMutex.Lock()
	defer autoRelayCacheMutex.Unlock()
	return autoRelayCache[network]
}
func getGwNodes(network models.NetworkID) []models.Node {
	autoRelayCacheMutex.Lock()
	defer autoRelayCacheMutex.Unlock()
	return gwNodesCache[network]
}

func setAutoRelayNodes(autoRelaynodes map[models.NetworkID][]models.Node, gwNodes map[models.NetworkID][]models.Node, currNodes []models.Node) {
	autoRelayCacheMutex.Lock()
	defer autoRelayCacheMutex.Unlock()
	autoRelayCache = autoRelaynodes
	gwNodesCache = gwNodes
	currentNodesCache = make(map[string]models.Node)
	for _, currNode := range currNodes {
		currentNodesCache[currNode.ID.String()] = currNode
	}

}

// processPeerSignal - processes the peer signals for any updates from peers
func processPeerSignal(signal models.Signal) {

	// process recieved new signal from peer
	// if signal is older than 3s ignore it,wait for a fresh signal from peer
	if time.Now().Unix()-signal.TimeStamp > 3 {
		return
	}
	switch signal.Action {
	case models.ConnNegotiation:
		if !isPeerExist(signal.FromHostPubKey) {
			return
		}
		devicePeer, err := wireguard.GetPeer(ncutils.GetInterfaceName(), signal.FromHostPubKey)
		if err != nil {
			return
		}
		// check if there is handshake on interface
		connected, err := networking.IsPeerConnected(devicePeer)
		if err != nil || connected {
			return
		}
		err = handlePeerRelaySignal(signal)
		if err != nil {
			logger.Log(2, fmt.Sprintf("Failed to perform action [%s]: %+v, Err: %v", signal.Action, signal.FromHostPubKey, err.Error()))
		}
	}

}

func handlePeerRelaySignal(signal models.Signal) error {
	fmt.Println("RECV signal from ", signal.FromNodeID)
	if !signal.Reply {
		// signal back
		err := SignalPeer(models.Signal{

			Server:         signal.Server,
			FromHostID:     signal.ToHostID,
			FromNodeID:     signal.ToNodeID,
			FromHostPubKey: signal.ToHostPubKey,
			ToHostPubKey:   signal.FromHostPubKey,
			ToHostID:       signal.FromHostID,
			ToNodeID:       signal.FromNodeID,
			Reply:          true,
			NetworkID:      signal.NetworkID,
			Action:         models.ConnNegotiation,
			TimeStamp:      time.Now().Unix(),
		})

		if err != nil {
			slog.Warn("failed to signal peer", "error", err.Error())
		} else {
			signalThrottleCache.Delete(signal.FromHostID)
		}
	} else {
		signalThrottleCache.Delete(signal.FromHostID)
	}
	autoRelayNodes := getAutoRelayNodes(models.NetworkID(signal.NetworkID))
	if len(autoRelayNodes) == 0 {
		return nil
	}
	server := config.GetServer(signal.Server)
	if server == nil {
		return errors.New("server config not found")
	}
	// check for nearest and healthy relay gw
	metricPort := server.MetricsPort
	if metricPort == 0 {
		metricPort = 51821
	}
	nearestNode, err := findNearestNode(autoRelayNodes, metricPort)
	if err != nil {
		slog.Error("failed to find nearest relay node", "error", err)
		return err
	}
	fmt.Println("====> Sending relay me req ", signal.FromNodeID)
	err = autoRelayME(http.MethodPost, signal.Server, signal.ToNodeID, signal.FromNodeID, nearestNode.ID.String())
	if err != nil {
		slog.Error("failed to signal server to relay me", "error", err)
		return err
	}

	return nil
}

// watchPeerConnections - periodically watches peer connections.
// if connection is bad, host will signal peers to use turn
func watchPeerConnections(ctx context.Context, waitg *sync.WaitGroup) {
	defer waitg.Done()
	autoRelayConnTicker = time.NewTicker(networking.PeerConnectionCheckInterval)
	defer autoRelayConnTicker.Stop()
	server := config.GetServer(config.CurrServer)
	if server == nil {
		return
	}
	metricPort := server.MetricsPort
	if metricPort == 0 {
		metricPort = 51821
	}
	for {
		select {
		case <-ctx.Done():
			slog.Info("exiting peer connection watcher")
			return
		case <-autoRelayConnTicker.C:
			go func() {
				// Exit early if context is done
				select {
				case <-ctx.Done():
					return
				default:
				}

				nodes := config.GetNodes()
				if len(nodes) == 0 {
					return
				}
				peerInfo, err := networking.GetPeerInfo()
				if err != nil {
					slog.Error("failed to get peer Info", "error", err)
					return
				}
				devicePeerMap, err := wireguard.GetPeersFromDevice(ncutils.GetInterfaceName())
				if err != nil {
					slog.Debug("failed to get peers from device: ", "error", err)
					return
				}
				for _, node := range nodes {
					// Check context before processing each node
					select {
					case <-ctx.Done():
						return
					default:
					}

					if node.Server != config.CurrServer {
						continue
					}
					if node.AutoAssignGateway {
						if currNode, ok := currentNodesCache[node.ID.String()]; ok {
							checkAssignGw(currNode)
						}
					} else {
						autoRelayNodes := getAutoRelayNodes(models.NetworkID(node.Network))
						if len(autoRelayNodes) > 0 {
							fmt.Println("CHECKING RELAY CTX for: ", node.ID.String(), node.Address.String())
							// check current relay in use is the closest
							if currNode, ok := currentNodesCache[node.ID.String()]; ok {

								if currNode.AutoRelayedBy != uuid.Nil {
									fmt.Println("checking if curr relay is closest")
									autoRelayNodes := getAutoRelayNodes(models.NetworkID(node.Network))
									if len(autoRelayNodes) > 0 {
										nearestNode, err := findNearestNode(autoRelayNodes, metricPort)
										if err == nil {
											fmt.Println("FOUND NEAREST: ", nearestNode.Address.IP.String())
											if currNode.AutoRelayedBy != nearestNode.ID {
												err = autoRelayME(http.MethodPut, server.Server, node.ID.String(), "", nearestNode.ID.String())
												if err != nil {
													fmt.Println("failed to switch to nearest relay node ", err)
												}
											}
										}

									}

								}

							}
						}

					}

					fmt.Println("=====> HERE1")
					peers, ok := peerInfo.NetworkPeerIDs[models.NetworkID(node.Network)]
					if !ok {
						continue
					}
					fmt.Println("=====> HERE2")
					for pubKey, peer := range peers {
						// Check context before processing each peer
						select {
						case <-ctx.Done():
							return
						default:
						}

						if peer.IsExtClient {
							continue
						}
						devicePeer, ok := devicePeerMap[pubKey]
						if !ok {
							continue
						}
						if cnt, ok := signalThrottleCache.Load(peer.HostID); ok && cnt.(int) > 3 {
							fmt.Println("======> Cache Hit ", peer.Address)
							continue
						}
						// check if there is handshake on interface
						connected, err := networking.IsPeerConnected(devicePeer)
						if err != nil || connected {
							continue
						}
						connected, _ = metrics.PeerConnStatus(peer.Address, metricPort, 2)
						if connected {
							// peer is connected,so continue
							continue
						}
						fmt.Println("=====> HERE3", peer.Address)
						// if err := checkAutoRelayCtxForPeer(config.CurrServer, node.ID.String(), peer.ID); err != nil {
						// 	slog.Error("auto relay ctx for peer ", "error", err)
						// 	continue
						// }
						fmt.Println("=====> Sending signal for peerr", peer.Address)
						s := models.Signal{
							Server:         config.CurrServer,
							FromHostID:     config.Netclient().ID.String(),
							ToHostID:       peer.HostID,
							FromNodeID:     node.ID.String(),
							ToNodeID:       peer.ID,
							FromHostPubKey: config.Netclient().PublicKey.String(),
							ToHostPubKey:   pubKey,
							Action:         models.ConnNegotiation,
							TimeStamp:      time.Now().Unix(),
						}
						server := config.GetServer(config.CurrServer)
						if server == nil {
							continue
						}
						// signal peer
						err = SignalPeer(s)
						if err != nil {
							logger.Log(2, "failed to signal peer: ", err.Error())
						} else {
							if cnt, ok := signalThrottleCache.Load(peer.HostID); ok {
								if cnt.(int) <= 3 {
									cnt := cnt.(int) + 1
									signalThrottleCache.Store(peer.HostID, cnt)
								}
							} else {
								signalThrottleCache.Store(peer.HostID, 1)
							}

						}

					}
				}
			}()

		}
	}
}

func isPeerExist(peerKey string) bool {
	_, err := wireguard.GetPeer(ncutils.GetInterfaceName(), peerKey)
	return err == nil
}

func checkAssignGw(node models.Node) {
	if !node.AutoAssignGateway {
		return
	}
	gwNodes := getGwNodes(models.NetworkID(node.Network))
	if len(gwNodes) == 0 {
		return
	}
	server := config.GetServer(config.CurrServer)
	if server == nil {
		return
	}
	metricPort := server.MetricsPort
	if metricPort == 0 {
		metricPort = 51821
	}
	// check if current gw is reachable
	if node.RelayedBy != "" {
		for _, gwNode := range gwNodes {
			if gwNode.ID.String() == node.RelayedBy {
				connected, _ := metrics.PeerConnStatus(node.Address.IP.String(), metricPort, 3)
				if !connected {
					err := autoRelayME(http.MethodPut, server.Server, node.ID.String(), "", "")
					if err != nil {
						fmt.Println("failed to switch to nearest gw node ", err)
					}
					time.Sleep(time.Second * 6)
				}
				break
			}
		}
	}
	fmt.Println("NO OF GwNODES: ", len(gwNodes))
	nearestNode, err := findNearestNode(gwNodes, metricPort)
	if err == nil {
		fmt.Println("FOUND NEAREST GW: ", nearestNode.Address.IP.String())
		if node.RelayedBy != nearestNode.ID.String() {
			err := autoRelayME(http.MethodPut, server.Server, node.ID.String(), "", nearestNode.ID.String())
			if err != nil {
				fmt.Println("failed to switch to nearest gw node ", err)
			}
		}
	} else if node.RelayedBy != "" {
		fmt.Println("=========> Sending signal to unrelay curr node")
		// current gw is unavailable, unrelay the node
		err := autoRelayME(http.MethodPut, server.Server, node.ID.String(), "", "")
		if err != nil {
			fmt.Println("failed to switch to nearest gw node ", err)
		}
	}

}

// findNearestNode finds the node with the lowest latency from a list of nodes
func findNearestNode(nodes []models.Node, metricPort int) (*models.Node, error) {
	if len(nodes) == 0 {
		return nil, errors.New("no relay nodes available")
	}

	var nearestNode *models.Node
	var lowestLatency int64 = 999 // Start with a very high value (milliseconds)

	for i := range nodes {
		node := &nodes[i]
		fmt.Println("=====>findNearestNode: ", node.Address.String())
		// Try to get metrics/ping the node to determine latency
		connected, latency := metrics.PeerConnStatus(node.Address.IP.String(), metricPort, 2)
		fmt.Println("=====> CONNECTION STATUS", node.Address, connected, latency)
		if !connected || latency <= 0 {
			// If we can't reach the node or got invalid latency, skip it
			fmt.Println("====> relay node unreachable", "node", node.ID.String(), "address", node.Address.String())
			continue
		}

		// Update nearest node if this one has lower latency
		if latency < lowestLatency {
			lowestLatency = latency
			nearestNode = node
			slog.Debug("found reachable relay node", "node", node.ID.String(), "latency_ms", latency)
		}
	}

	// If no node was reachable, return error
	if nearestNode == nil {
		return nil, errors.New("no reachable relay nodes found")
	}

	return nearestNode, nil
}

// autoRelayME - signals the server to auto relay
func autoRelayME(method, serverName, nodeID, peernodeID, relayID string) error {
	server := config.GetServer(serverName)
	if server == nil {
		return errors.New("server config not found")
	}
	host := config.Netclient()
	if host == nil {
		return fmt.Errorf("no configured host found")
	}
	token, err := auth.Authenticate(server, host)
	if err != nil {
		return err
	}
	endpoint := httpclient.JSONEndpoint[models.SuccessResponse, models.ErrorResponse]{
		URL:           "https://" + server.API,
		Route:         fmt.Sprintf("/api/v1/node/%s/auto_relay_me", nodeID),
		Method:        method,
		Data:          models.AutoRelayMeReq{NodeID: peernodeID, AutoRelayGwID: relayID},
		Authorization: "Bearer " + token,
		ErrorResponse: models.ErrorResponse{},
	}
	resp, errData, err := endpoint.GetJSON(models.SuccessResponse{}, models.ErrorResponse{})
	if err != nil {
		fmt.Println("+===> RELAY ME: ", resp.Message, endpoint.Method)
		if errors.Is(err, httpclient.ErrStatus) {
			slog.Error("error asking server to relay me", "code", strconv.Itoa(errData.Code), "error", errData.Message)
		}
		return err
	}
	return nil
}

// SignalPeer - signals the peer with host's turn relay endpoint
func SignalPeer(signal models.Signal) error {
	return publishPeerSignal(signal)
}
