package functions

import (
	"context"
	"encoding/json"
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
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	// peerConnectionCheckInterval - time interval to check peer connection status
	peerConnectionCheckInterval = time.Second * 30
	// LastHandShakeThreshold - threshold for considering inactive connection
	LastHandShakeThreshold = time.Minute * 3
	peerConnTicker         *time.Ticker
	signalThrottleCache    = sync.Map{}
)

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
		connected, err := isPeerConnected(devicePeer)
		if err != nil || connected {
			return
		}
		err = handlePeerFailOver(signal)
		if err != nil {
			logger.Log(2, fmt.Sprintf("Failed to perform action [%s]: %+v, Err: %v", signal.Action, signal.FromHostPubKey, err.Error()))
		}
	}

}

func handlePeerFailOver(signal models.Signal) error {
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

	// Start TCP proxy for this peer if UDP fails
	failoverProxy := GetFailoverTCPProxy()
	peerEndpoint := fmt.Sprintf("%s:%d", signal.Server, 51820) // Default WireGuard port
	err := failoverProxy.StartTCPProxyForPeer(signal.FromHostPubKey, peerEndpoint)
	if err != nil {
		slog.Warn("failed to start TCP proxy for peer", "peer", signal.FromHostPubKey, "error", err)
	}

	err = failOverMe(signal.Server, signal.ToNodeID, signal.FromNodeID)
	if err != nil {
		slog.Debug("failed to signal server to relay me", "error", err)
	}

	return nil
}

func checkPeerEndpoints(ctx context.Context, waitg *sync.WaitGroup) {
	defer waitg.Done()
	peerConnTicker = time.NewTicker(peerConnectionCheckInterval)
	defer peerConnTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("exiting peer connection watcher")
			return
		case <-peerConnTicker.C:
			go func() {
				nodes := config.GetNodes()
				if len(nodes) == 0 {
					return
				}
				peerInfo, err := getPeerInfo()
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
					if !failOverExists(node) {
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
					}
				}
			}()

		}
	}
}

// watchPeerConnections - periodically watches peer connections.
// if connection is bad, host will signal peers to use turn
func watchPeerConnections(ctx context.Context, waitg *sync.WaitGroup) {
	defer waitg.Done()
	peerConnTicker = time.NewTicker(peerConnectionCheckInterval)
	defer peerConnTicker.Stop()
	metricPort := config.GetServer(config.CurrServer).MetricsPort
	if metricPort == 0 {
		metricPort = 51821
	}
	for {
		select {
		case <-ctx.Done():
			slog.Info("exiting peer connection watcher")
			return
		case <-peerConnTicker.C:
			go func() {
				nodes := config.GetNodes()
				if len(nodes) == 0 {
					return
				}
				peerInfo, err := getPeerInfo()
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
					if !failOverExists(node) {
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
						connected, err := isPeerConnected(devicePeer)
						if err != nil || connected {
							// UDP connection is working, stop TCP proxy if it exists
							StopTCPProxyForPeer(pubKey)
							continue
						}
						fmt.Printf("====> CHECKING PEER CONN: %+v\n", devicePeer)
						connected, _ = metrics.PeerConnStatus(peer.Address, metricPort, 2)
						if connected {
							// peer is connected,so continue
							continue
						}
						if checkFailOverCtxForPeer(config.CurrServer, node.ID.String(), peer.ID) != nil {
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
						if Mqclient != nil && Mqclient.IsConnectionOpen() {
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
				}
			}()

		}
	}
}

func isPeerExist(peerKey string) bool {
	_, err := wireguard.GetPeer(ncutils.GetInterfaceName(), peerKey)
	return err == nil
}

func failOverExists(node config.Node) bool {
	server := config.GetServer(node.Server)
	if server == nil {
		return false
	}
	token, err := auth.Authenticate(server, config.Netclient())
	if err != nil {
		slog.Warn("failed to authenticate when checking failover node", err.Error())
		return false
	}

	url := fmt.Sprintf("https://%s/api/v1/node/%s/failover", server.API, node.ID)
	endpoint := httpclient.JSONEndpoint[models.Node, models.ErrorResponse]{
		URL:           url,
		Method:        http.MethodGet,
		Authorization: "Bearer " + token,
		Data:          nil,
		Response:      models.Node{},
		ErrorResponse: models.ErrorResponse{},
	}
	_, errData, err := endpoint.GetJSON(models.Node{}, models.ErrorResponse{})
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			slog.Warn("status error calling ", endpoint.URL, errData.Message)
			return false
		}
		slog.Warn("no failover node returned", err.Error())
		return false
	}

	return true
}

func getPeerInfo() (models.HostPeerInfo, error) {

	server := config.GetServer(config.CurrServer)
	if server == nil {
		return models.HostPeerInfo{}, errors.New("server is nil")
	}
	token, err := auth.Authenticate(server, config.Netclient())
	if err != nil {
		logger.Log(1, "failed to authenticate when publishing metrics", err.Error())
		return models.HostPeerInfo{}, err
	}
	url := fmt.Sprintf("https://%s/api/v1/host/%s/peer_info", server.API, config.Netclient().ID.String())
	endpoint := httpclient.JSONEndpoint[models.SuccessResponse, models.ErrorResponse]{
		URL:           url,
		Method:        http.MethodGet,
		Authorization: "Bearer " + token,
		Data:          nil,
		Response:      models.SuccessResponse{},
		ErrorResponse: models.ErrorResponse{},
	}
	response, errData, err := endpoint.GetJSON(models.SuccessResponse{}, models.ErrorResponse{})
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			logger.Log(0, "status error calling ", endpoint.URL, errData.Message)
			return models.HostPeerInfo{}, err
		}
		slog.Error("failed to read peer info resp", "error", err.Error())
		return models.HostPeerInfo{}, err
	}
	peerInfo := models.HostPeerInfo{}
	data, _ := json.Marshal(response.Response)
	err = json.Unmarshal(data, &peerInfo)
	if err != nil {
		return models.HostPeerInfo{}, err
	}
	return peerInfo, nil
}

func checkFailOverCtxForPeer(serverName, nodeID, peernodeID string) error {
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
		Route:         fmt.Sprintf("/api/v1/node/%s/failover_check", nodeID),
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

// failOverMe - signals the server to failOver ME
func failOverMe(serverName, nodeID, peernodeID string) error {
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
		Route:         fmt.Sprintf("/api/v1/node/%s/failover_me", nodeID),
		Method:        http.MethodPost,
		Data:          models.FailOverMeReq{NodeID: peernodeID},
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
	return publishPeerSignal(config.CurrServer, signal)
}

// isPeerConnected - get peer connection status by checking last handshake time
func isPeerConnected(peer wgtypes.Peer) (connected bool, err error) {
	if !peer.LastHandshakeTime.IsZero() && !(time.Since(peer.LastHandshakeTime) > LastHandShakeThreshold) {
		connected = true
	}
	return
}

// StopTCPProxyForPeer stops the TCP proxy for a peer when UDP connection is restored
func StopTCPProxyForPeer(peerKey string) {
	failoverProxy := GetFailoverTCPProxy()
	if failoverProxy.IsPeerUsingTCPProxy(peerKey) {
		failoverProxy.StopTCPProxyForPeer(peerKey)
		slog.Info("stopped TCP proxy for peer due to UDP connection restoration", "peer", peerKey)
	}
}
