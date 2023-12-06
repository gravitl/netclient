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
	"github.com/gravitl/netclient/config"
	ncconfig "github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/metrics"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	nm_models "github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

var (
	// peerConnectionCheckInterval - time interval to check peer connection status
	peerConnectionCheckInterval = time.Second * 25
	// LastHandShakeThreshold - threshold for considering inactive connection
	LastHandShakeThreshold = time.Minute * 3

	ResetCh = make(chan struct{}, 2)
)

// processPeerSignal - processes the peer signals for any updates from peers
func processPeerSignal(signal models.Signal) {

	// process recieved new signal from peer
	// if signal is older than 10s ignore it,wait for a fresh signal from peer
	if time.Now().Unix()-signal.TimeStamp > 5 {
		return
	}
	switch signal.Action {
	case nm_models.ConnNegotiation:
		if !isPeerExist(signal.FromHostPubKey) {
			return
		}
		err := handlePeerFailOver(signal)
		if err != nil {
			logger.Log(2, fmt.Sprintf("Failed to perform action [%s]: %+v, Err: %v", signal.Action, signal.FromHostPubKey, err.Error()))
		}
	}

}

func handlePeerFailOver(signal nm_models.Signal) error {
	if !signal.Reply {
		// signal back
		err := SignalPeer(nm_models.Signal{
			Server:         signal.Server,
			FromHostID:     signal.ToHostID,
			FromNodeID:     signal.ToNodeID,
			FromHostPubKey: signal.ToHostPubKey,
			ToHostPubKey:   signal.FromHostPubKey,
			ToHostID:       signal.FromHostID,
			ToNodeID:       signal.FromNodeID,
			Reply:          true,
			Action:         nm_models.ConnNegotiation,
			TimeStamp:      time.Now().Unix(),
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

// watchPeerConnections - periodically watches peer connections.
// if connection is bad, host will signal peers to use turn
func watchPeerConnections(ctx context.Context, waitg *sync.WaitGroup) {
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
			nodes := ncconfig.GetNodes()
			if len(nodes) == 0 {
				continue
			}
			for _, node := range nodes {
				if node.Server != ncconfig.CurrServer {
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
					connected, _ := metrics.PeerConnStatus(peer.Address, peer.ListenPort)
					if connected {
						// peer is connected,so continue
						continue
					}
					s := nm_models.Signal{
						Server:         ncconfig.CurrServer,
						FromHostID:     ncconfig.Netclient().ID.String(),
						ToHostID:       peer.HostID,
						FromNodeID:     node.ID.String(),
						ToNodeID:       peer.ID,
						FromHostPubKey: config.Netclient().PublicKey.String(),
						ToHostPubKey:   pubKey,
						Action:         nm_models.ConnNegotiation,
						TimeStamp:      time.Now().Unix(),
					}
					server := config.GetServer(ncconfig.CurrServer)
					if server == nil {
						continue
					}
					// signal peer
					err = SignalPeer(s)
					if err != nil {
						logger.Log(2, "failed to signal peer: ", err.Error())
					}

				}
			}

		}
	}
}

func isPeerExist(peerKey string) bool {
	_, err := wireguard.GetPeer(ncutils.GetInterfaceName(), peerKey)
	return err == nil
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

// failOverMe - signals the server to failOver ME
func failOverMe(serverName, nodeID, peernodeID string) error {
	server := ncconfig.GetServer(serverName)
	if server == nil {
		return errors.New("server config not found")
	}
	host := ncconfig.Netclient()
	if host == nil {
		return fmt.Errorf("no configured host found")
	}
	token, err := auth.Authenticate(server, host)
	if err != nil {
		return err
	}
	endpoint := httpclient.JSONEndpoint[nm_models.SuccessResponse, nm_models.ErrorResponse]{
		URL:           "https://" + server.API,
		Route:         fmt.Sprintf("/api/v1/node/%s/failover_me", nodeID),
		Method:        http.MethodPost,
		Data:          nm_models.FailOverMeReq{NodeID: peernodeID},
		Authorization: "Bearer " + token,
		ErrorResponse: nm_models.ErrorResponse{},
	}
	_, errData, err := endpoint.GetJSON(nm_models.SuccessResponse{}, nm_models.ErrorResponse{})
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			slog.Error("error asking server to relay me", "code", strconv.Itoa(errData.Code), "error", errData.Message)
		}
		return err
	}
	return nil
}

// SignalPeer - signals the peer with host's turn relay endpoint
func SignalPeer(signal nm_models.Signal) error {
	return publishPeerSignal(config.CurrServer, signal)
}
