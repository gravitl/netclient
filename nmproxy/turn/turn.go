package turn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/auth"
	ncconfig "github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/nmproxy/packet"
	"github.com/gravitl/netclient/nmproxy/server"
	wireguard "github.com/gravitl/netclient/nmproxy/wg"
	"github.com/gravitl/netmaker/logger"
	nm_models "github.com/gravitl/netmaker/models"
	"github.com/pion/logging"
	"github.com/pion/turn/v2"
	"gortc.io/stun"
)

// Init - start's the turn client for all the present turn configs
func Init(ctx context.Context, wg *sync.WaitGroup, turnCfgs []ncconfig.TurnConfig) {
	for _, turnCfgI := range turnCfgs {
		if turnCfgI.Server == "" || turnCfgI.Domain == "" || turnCfgI.Port == 0 {
			continue
		}
		err := startClient(turnCfgI.Server, turnCfgI.Domain, turnCfgI.Port)
		if err != nil {
			logger.Log(0, "failed to start turn client: ", err.Error())
			continue
		}
		resetCh := make(chan struct{}, 1)
		wg.Add(1)
		go startTurnListener(ctx, wg, turnCfgI.Server, resetCh)
		wg.Add(1)
		go createOrRefreshPermissions(ctx, wg, turnCfgI.Server, resetCh)
	}
}

// startClient - starts the turn client and allocates itself address on the turn server provided
func startClient(server, turnDomain string, turnPort int) error {
	conn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		logger.Log(0, "Failed to listen: %s", err.Error())
		return err
	}
	turnServerAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", turnDomain, turnPort))
	if err != nil {
		return err
	}
	cfg := &turn.ClientConfig{
		STUNServerAddr: turnServerAddr.String(),
		TURNServerAddr: turnServerAddr.String(),
		Conn:           conn,
		Username:       ncconfig.Netclient().ID.String(),
		Password:       ncutils.ConvHostPassToHash(ncconfig.Netclient().HostPass),
		Realm:          turnDomain,
		Software:       "netmaker",
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	}
	client, err := turn.NewClient(cfg)
	if err != nil {
		logger.Log(0, "Failed to create TURN client: %s", err.Error())
		conn.Close()
		return err
	}
	err = client.Listen()
	if err != nil {
		return err
	}

	config.GetCfg().SetTurnCfg(&models.TurnCfg{
		Mutex:  &sync.RWMutex{},
		Cfg:    cfg,
		Client: client,
		Status: true,
	})

	return nil
}

func allocateAddr(client *turn.Client) (net.PacketConn, error) {
	// Allocate a relay socket on the TURN server. On success, it
	// will return a net.PacketConn which represents the remote
	// socket.
	relayConn, err := client.Allocate()
	if err != nil {
		logger.Log(0, "Failed to allocate: ", err.Error())
		return nil, err
	}
	// Send BindingRequest to learn our external IP
	mappedAddr, err := client.SendBindingRequest()
	if err != nil {
		logger.Log(0, "failed to send binding req: ", err.Error())
		return nil, err
	}
	// Punch a UDP hole for the relayConn by sending a data to the mappedAddr.
	// This will trigger a TURN client to generate a permission request to the
	// TURN server. After this, packets from the IP address will be accepted by
	// the TURN server.
	_, err = relayConn.WriteTo([]byte("Hello"), mappedAddr)
	if err != nil {
		logger.Log(0, "failed to send binding request: ", err.Error())
		return nil, err
	}
	// The relayConn's local address is actually the transport
	// address assigned on the TURN server.
	log.Printf("relayed-address=%s", relayConn.LocalAddr().String())
	return relayConn, nil
}

// SignalPeer - signals the peer with host's turn relay endpoint
func SignalPeer(serverName string, signal nm_models.Signal) error {
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
	logger.Log(4, fmt.Sprintf("Sending Signal to Peer: %+v", signal))
	endpoint := httpclient.JSONEndpoint[nm_models.Signal, nm_models.ErrorResponse]{
		URL:           "https://" + server.API,
		Route:         fmt.Sprintf("/api/v1/host/%s/signalpeer", ncconfig.Netclient().ID.String()),
		Method:        http.MethodPost,
		Authorization: "Bearer " + token,
		Data:          signal,
		Response:      nm_models.Signal{},
		ErrorResponse: nm_models.ErrorResponse{},
	}
	_, errData, err := endpoint.GetJSON(nm_models.Signal{}, nm_models.ErrorResponse{})
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			logger.Log(0, "error signalling peer", strconv.Itoa(errData.Code), errData.Message)
		}
		return err
	}
	return nil
}

func listen(wg *sync.WaitGroup, serverName string, turnConn net.PacketConn) {
	logger.Log(0, "Starting Turn Listener: ", turnConn.LocalAddr().String(), serverName)
	defer wg.Done()
	buffer := make([]byte, packet.DefaultBodySize)
	for {
		n, addr, err := turnConn.ReadFrom(buffer)
		if err != nil {
			logger.Log(0, "failed to read from remote conn: ", err.Error())
			return
		}
		server.ProcessIncomingPacket(n, addr.String(), buffer)
	}
}

// startTurnListener - listens for incoming packets from peers
func startTurnListener(ctx context.Context, wg *sync.WaitGroup, serverName string, resetCh chan struct{}) {
	defer wg.Done()
	defer logger.Log(0, "Closing turn conn: ", serverName)
	t := config.GetCfg().GetTurnCfg()
	if t == nil {
		return
	}
	t.Mutex.Lock()
	turnConn, err := allocateAddr(t.Client)
	if err != nil {
		logger.Log(0, "failed to allocate addr on turn: ", err.Error())
		t.Status = false
	} else {
		t.TurnConn = turnConn
		t.Status = true
	}
	config.GetCfg().SetTurnCfg(t)
	t.Mutex.Unlock()
	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		<-ctx.Done()
		t := config.GetCfg().GetTurnCfg()
		if t != nil && t.TurnConn != nil {
			t.Mutex.Lock()
			t.TurnConn.Close()
			t.Mutex.Unlock()
		}
	}(wg)
	if t.Status {
		wg.Add(1)
		go listen(wg, serverName, turnConn)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-resetCh:
			iface, err := wireguard.GetWgIface(ncutils.GetInterfaceName())
			if err != nil {
				logger.Log(0, "failed to iface: ", err.Error())
				continue
			}
			t := config.GetCfg().GetTurnCfg()
			if t == nil || t.TurnConn == nil {
				continue
			}
			t.Mutex.Lock()
			t.TurnConn.Close()
			// reallocate addr and signal all the peers
			logger.Log(0, "## Reintializing Turn Endpoint on server:", serverName)
			if t.Client == nil {
				t.Mutex.Unlock()
				continue
			}
			turnConn, err := allocateAddr(t.Client)
			if err != nil {
				logger.Log(0, "failed to allocate addr on turn: ", err.Error())
				t.Status = false
				config.GetCfg().SetTurnCfg(t)
				go func() {
					// need to retry to allocate addr again on turn server
					time.Sleep(time.Second * 30)
					if resetCh != nil {
						resetCh <- struct{}{}
					}
				}()
				t.Mutex.Unlock()
				continue
			}
			t.TurnConn = turnConn
			t.Status = true
			config.GetCfg().SetTurnCfg(t)
			t.Mutex.Unlock()
			turnPeersMap := config.GetCfg().GetAllTurnPeersCfg()
			for peerKey := range turnPeersMap {
				err := SignalPeer(serverName, nm_models.Signal{
					Server:            serverName,
					FromHostPubKey:    iface.Device.PublicKey.String(),
					TurnRelayEndpoint: turnConn.LocalAddr().String(),
					ToHostPubKey:      peerKey,
					Action:            nm_models.ConnNegotiation,
				})
				if err != nil {
					logger.Log(0, "failed to signal peer: ", err.Error())
					continue
				}
				if conn, ok := config.GetCfg().GetPeer(peerKey); ok {
					logger.Log(0, "Resetting Peer Conn: ", peerKey)
					conn.Config.TurnConn = turnConn
					config.GetCfg().UpdatePeer(&conn)
					config.GetCfg().ResetPeer(peerKey)
				}
			}
			wg.Add(1)
			go listen(wg, serverName, t.TurnConn)
		}
	}
}

// createOrRefreshPermissions - creates or refreshes's peer permission on turn server
func createOrRefreshPermissions(ctx context.Context, wg *sync.WaitGroup, serverName string, resetCh chan struct{}) {
	defer wg.Done()
	ticker := time.NewTicker(time.Minute * 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t := config.GetCfg().GetTurnCfg()
			if t == nil {
				return
			}
			if t.Client == nil || t.TurnConn == nil || t.Cfg.Conn == nil {
				continue
			}
			if !t.Status {
				continue
			}
			t.Mutex.RLock()
			addrs := []net.Addr{}
			turnPeersMap := config.GetCfg().GetAllTurnPeersCfg()
			for _, cfg := range turnPeersMap {
				if cfg.PeerTurnAddr == "" {
					continue
				}
				peerTurnEndpoint, err := net.ResolveUDPAddr("udp", cfg.PeerTurnAddr)
				if err != nil {
					continue
				}
				addrs = append(addrs, peerTurnEndpoint)

			}
			if len(addrs) == 0 {
				t.Mutex.RUnlock()
				continue
			}
			err := t.Client.CreatePermission(addrs...)
			if err != nil {
				resfrshErrType := stun.NewType(stun.MethodRefresh, stun.ClassErrorResponse)
				permissionErrType := stun.NewType(stun.MethodCreatePermission, stun.ClassErrorResponse)
				logger.Log(2, "failed to refresh permission for peers: ", err.Error())
				if strings.Contains(err.Error(), resfrshErrType.String()) ||
					strings.Contains(err.Error(), permissionErrType.String()) ||
					strings.Contains(err.Error(), "all retransmissions failed") {
					logger.Log(0, "Resetting turn client....")

					resetCh <- struct{}{}
				}
			}
			t.Mutex.RUnlock()
		}
	}
}
