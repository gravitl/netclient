package networking

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/cache"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

var (
	// PeerConnectionCheckInterval - time interval to check peer connection status
	PeerConnectionCheckInterval = time.Second * 15
	// LastHandShakeThreshold - threshold for considering inactive connection
	LastHandShakeThreshold = time.Minute * 3
	//
	PeerLocalEndpointConnTicker *time.Ticker
)

func tryLocalConnect(peerIp, peerPubKey string, metricsPort int) bool {
	parsePeerIp := net.ParseIP(peerIp)
	if parsePeerIp.To4() == nil {
		// ipv6
		peerIp = fmt.Sprintf("[%s]", peerIp)
	}
	var conn net.Conn
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	var err error
	for i := 0; i < 5; i++ {
		addr := fmt.Sprintf("%s:%d", peerIp, metricsPort)
		conn, err = net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			continue
		}
		message, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil && err.Error() != "EOF" {
			continue
		}
		parts := strings.Split(strings.TrimSpace(message), "|")
		if len(parts) == 0 {
			continue
		}
		if parts[0] == messages.Success || parts[0] == peerPubKey {
			return true
		}
		time.Sleep(time.Second * 5)
	}
	return false

}

// FindBestEndpoint - requests against a given addr and port
func FindBestEndpoint(peerIp, peerPubKey string, peerListenPort, metricsPort int) {
	connected := tryLocalConnect(peerIp, peerPubKey, metricsPort)
	if connected {
		parsePeerIp := net.ParseIP(peerIp)
		if parsePeerIp.To16() != nil {
			// ipv6
			peerIp = fmt.Sprintf("[%s]", peerIp)
		}
		peerEndpoint, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", peerIp, peerListenPort))
		if err != nil {
			slog.Error("failed to parse peer udp addr", "peeraddr", fmt.Sprintf("%s:%d", peerIp, peerListenPort), "err", err.Error())
			return
		}
		storeNewPeerIface(peerPubKey, peerEndpoint)
	} else {
		if retryCnt, ok := cache.SkipEndpointCache.Load(peerPubKey); ok {
			cnt := retryCnt.(int)
			if cnt <= 3 {
				cnt += 1
				cache.SkipEndpointCache.Store(peerPubKey, cnt)
			}
		} else {
			cache.SkipEndpointCache.Store(peerPubKey, 1)
		}
	}
}

func CheckPeerEndpoints(ctx context.Context, waitg *sync.WaitGroup) {
	defer waitg.Done()
	PeerLocalEndpointConnTicker = time.NewTicker(PeerConnectionCheckInterval)
	defer PeerLocalEndpointConnTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("exiting peer connection watcher")
			return
		case <-PeerLocalEndpointConnTicker.C:
			go func() {
				nodes := config.GetNodes()
				if len(nodes) == 0 {
					return
				}
				peerInfo, err := GetPeerInfo()
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
							SetPeerEndpoint(pubKey, cache.EndpointCacheValue{Endpoint: localEndpoint})
						}
					}
				}
			}()

		}
	}
}

func GetPeerInfo() (models.HostPeerInfo, error) {

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
