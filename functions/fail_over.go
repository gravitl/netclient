package functions

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/metrics"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

var (
	// peerConnectionCheckInterval - time interval to check peer connection status
	peerConnectionCheckInterval = time.Second * 25
	// LastHandShakeThreshold - threshold for considering inactive connection
	LastHandShakeThreshold = time.Minute * 3
	peerConnTicker         *time.Ticker
)

// processPeerSignal - processes the peer signals for any updates from peers
func processPeerSignal(signal models.Signal) {

	// process recieved new signal from peer
	// if signal is older than 10s ignore it,wait for a fresh signal from peer
	if time.Now().Unix()-signal.TimeStamp > 5 {
		return
	}
	switch signal.Action {
	case models.ConnNegotiation:
		if !isPeerExist(signal.FromHostPubKey) {
			return
		}
		err := handlePeerFailOver(signal)
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
			slog.Error("failed to signal peer", "error", err.Error())
		}
	}

	if config.Netclient().NatType == models.NAT_Types.BehindNAT {
		err := failOverMe(signal.Server, signal.ToNodeID, signal.FromNodeID)
		if err != nil {
			slog.Debug("failed to signal server to relay me", "error", err)
		}
	}
	return nil
}

// watchPeerConnections - periodically watches peer connections.
// if connection is bad, host will signal peers to use turn
func watchPeerConnections(ctx context.Context, waitg *sync.WaitGroup) {
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
				for _, node := range nodes {
					if node.Server != config.CurrServer {
						continue
					}
					peers, err := getPeerInfo(node)
					if err != nil {
						slog.Error("failed to get peer Info", "error", err)
						continue
					}
					for pubKey, peer := range peers {
						if peer.IsExtClient {
							continue
						}
						connected, _ := metrics.PeerConnStatus(peer.Address, peer.ListenPort, 2)
						if connected {
							// peer is connected,so continue
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

func getPeerInfo(node config.Node) (models.PeerMap, error) {
	server := config.GetServer(node.Server)
	if server == nil {
		return nil, errors.New("server is nil")
	}
	token, err := auth.Authenticate(server, config.Netclient())
	if err != nil {
		logger.Log(1, "failed to authenticate when publishing metrics", err.Error())
		return nil, err
	}
	url := fmt.Sprintf("https://%s/api/nodes/%s/%s", server.API, node.Network, node.ID)
	endpoint := httpclient.JSONEndpoint[models.NodeGet, models.ErrorResponse]{
		URL:           url,
		Method:        http.MethodGet,
		Authorization: "Bearer " + token,
		Data:          nil,
		Response:      models.NodeGet{},
		ErrorResponse: models.ErrorResponse{},
	}
	response, errData, err := endpoint.GetJSON(models.NodeGet{}, models.ErrorResponse{})
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
		Route:         fmt.Sprintf("/api/v1/node/%s/failover_me", url.QueryEscape(nodeID)),
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
