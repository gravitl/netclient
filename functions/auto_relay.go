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
	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/cache"
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
	autoRelayCache      = make(map[models.NetworkID][]models.Node)

	autoRelayConnTicker *time.Ticker
	signalThrottleCache = sync.Map{}
)

func getAutoRelayNodes(network models.NetworkID) []models.Node {
	autoRelayCacheMutex.Lock()
	defer autoRelayCacheMutex.Unlock()
	return autoRelayCache[network]
}

func setAutoRelayNodes(nodes map[models.NetworkID][]models.Node) {
	autoRelayCacheMutex.Lock()
	defer autoRelayCacheMutex.Unlock()
	autoRelayCache = nodes
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
	// check for nearest and healthy relay gw
	metricPort := config.GetServer(signal.Server).MetricsPort
	if metricPort == 0 {
		metricPort = 51821
	}
	nearestNode, err := findNearestNode(autoRelayNodes, metricPort)
	if err != nil {
		slog.Debug("failed to find nearest relay node", "error", err)
		return err
	}

	err = autoRelayME(signal.Server, signal.ToNodeID, signal.FromNodeID, nearestNode.ID.String())
	if err != nil {
		slog.Debug("failed to signal server to relay me", "error", err)
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
	metricPort := config.GetServer(config.CurrServer).MetricsPort
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
					if node.Server != config.CurrServer {
						continue
					}
					autoRelayNodes := getAutoRelayNodes(models.NetworkID(node.Network))
					if len(autoRelayNodes) == 0 {
						continue
					}
					peers, ok := peerInfo.NetworkPeerIDs[models.NetworkID(node.Network)]
					if !ok {
						continue
					}

					for pubKey, peer := range peers {
						if peer.IsExtClient {
							continue
						}
						devicePeer, ok := devicePeerMap[pubKey]
						if !ok {
							continue
						}
						// check if local endpoint is present
						localEndpoint, ok := wireguard.GetBetterEndpoint(pubKey)
						if ok && !devicePeer.Endpoint.IP.Equal(localEndpoint.IP) {
							networking.SetPeerEndpoint(pubKey, cache.EndpointCacheValue{Endpoint: localEndpoint})
						}
						if cnt, ok := signalThrottleCache.Load(peer.HostID); ok && cnt.(int) > 3 {
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
						if checkAutoRelayCtxForPeer(config.CurrServer, node.ID.String(), peer.ID) != nil {
							continue
						}
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

// findNearestNode finds the node with the lowest latency from a list of nodes
func findNearestNode(nodes []models.Node, metricPort int) (*models.Node, error) {
	if len(nodes) == 0 {
		return nil, errors.New("no relay nodes available")
	}

	var nearestNode *models.Node
	var lowestLatency int64 = 9999999 // Start with a very high value (milliseconds)

	for i := range nodes {
		node := &nodes[i]

		// Try to get metrics/ping the node to determine latency
		connected, latency := metrics.PeerConnStatus(node.Address.String(), metricPort, 2)

		if !connected || latency <= 0 {
			// If we can't reach the node or got invalid latency, skip it
			slog.Debug("relay node unreachable", "node", node.ID.String(), "address", node.Address.String())
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

func checkAutoRelayCtxForPeer(serverName, nodeID, peernodeID string) error {
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
		Route:         fmt.Sprintf("/api/v1/node/%s/auto_relay_check", nodeID),
		Method:        http.MethodGet,
		Data:          models.FailOverMeReq{NodeID: peernodeID},
		Authorization: "Bearer " + token,
		ErrorResponse: models.ErrorResponse{},
	}
	_, errData, err := endpoint.GetJSON(models.SuccessResponse{}, models.ErrorResponse{})
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			slog.Debug("error asking to check failover ctx", "code", strconv.Itoa(errData.Code), "error", errData.Message)
		}
		return err
	}
	return nil
}

// autoRelayME - signals the server to auto relay
func autoRelayME(serverName, nodeID, peernodeID, relayID string) error {
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
		Method:        http.MethodPost,
		Data:          models.AutoRelayMeReq{NodeID: peernodeID, AutoRelayGwID: relayID},
		Authorization: "Bearer " + token,
		ErrorResponse: models.ErrorResponse{},
	}
	_, errData, err := endpoint.GetJSON(models.SuccessResponse{}, models.ErrorResponse{})
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			slog.Debug("error asking server to relay me", "code", strconv.Itoa(errData.Code), "error", errData.Message)
		}
		return err
	}
	return nil
}

// SignalPeer - signals the peer with host's turn relay endpoint
func SignalPeer(signal models.Signal) error {
	return publishPeerSignal(signal)
}
