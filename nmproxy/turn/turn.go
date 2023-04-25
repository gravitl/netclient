package turn

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/auth"
	ncconfig "github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/nmproxy/packet"
	"github.com/gravitl/netclient/nmproxy/server"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/logic"
	nm_models "github.com/gravitl/netmaker/models"
	"github.com/pion/logging"
	turn "github.com/pion/turn/v2"
	"gortc.io/stun"
)

// Init - start's the turn client for all the present turn configs
func Init(ctx context.Context, wg *sync.WaitGroup, turnCfgs []ncconfig.TurnConfig) {
	for _, turnCfgI := range turnCfgs {
		err := startClient(turnCfgI.Server, turnCfgI.Domain, turnCfgI.Port)
		if err != nil {
			logger.Log(0, "failed to start turn client: ", err.Error())
			continue
		}
		resetCh := make(chan struct{}, 1)
		wg.Add(1)
		go startTurnListener(ctx, wg, turnCfgI.Server, resetCh)
		wg.Add(1)
		go addPeerListener(ctx, wg, turnCfgI.Server, resetCh)
		wg.Add(1)
		go createOrRefreshPermissions(ctx, wg, turnCfgI.Server)
	}
}

// startClient - starts the turn client and allocates itself address on the turn server provided
func startClient(server, turnDomain string, turnPort int) error {
	conn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		logger.Log(0, "Failed to listen: %s", err.Error())
		return err
	}
	turnServerAddr := fmt.Sprintf("%s:%d", turnDomain, turnPort)
	cfg := &turn.ClientConfig{
		STUNServerAddr: turnServerAddr,
		TURNServerAddr: turnServerAddr,
		Conn:           conn,
		Username:       ncconfig.Netclient().ID.String(),
		Password:       logic.ConvHostPassToHash(ncconfig.Netclient().HostPass),
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

	config.GetCfg().SetTurnCfg(server, models.TurnCfg{
		Cfg:    cfg,
		Client: client,
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
	host := ncconfig.Netclient()
	if host == nil {
		return fmt.Errorf("no configured host found")
	}
	token, err := auth.Authenticate(server, host)
	if err != nil {
		return err
	}
	logger.Log(0, fmt.Sprintf("-------> Sending Signal to Peer: %+v", signal))
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
		//if errors.Is(err, httpclient.ErrStatus) {
		logger.Log(0, "error signalling peer", strconv.Itoa(errData.Code), errData.Message)
		//}
		return err
	}
	return nil
}

// startTurnListener - start's turn client listener
func startTurnListener(ctx context.Context, wg *sync.WaitGroup, serverName string, resetCh chan struct{}) (reset bool) {
	defer wg.Done()
	t, ok := config.GetCfg().GetTurnCfg(serverName)
	if !ok {
		return
	}
	stunMgsMap := make(map[string]struct{})
	buf := make([]byte, 65535)
	for {

		n, from, err := t.Cfg.Conn.ReadFrom(buf)
		if err != nil {
			logger.Log(0, "exiting read loop: %s", err.Error())
			return
		}
		handled, err := t.Client.HandleInbound(buf[:n], from)
		if err != nil {
			logger.Log(0, "------>read loop: %s", err.Error())
			continue

		}
		if handled && stun.IsMessage(buf[:n]) {
			msg := &stun.Message{Raw: buf[:n]}
			if err := msg.Decode(); err != nil {
				continue
			}
			if msg.Type.Class == stun.ClassErrorResponse {
				fmt.Println("##########################")
				fmt.Printf("Msg : %+v\n", msg.Type)
				fmt.Printf("ID : %s\n", base64.StdEncoding.EncodeToString(msg.TransactionID[:]))
				fmt.Printf("RAW : %s\n", base64.StdEncoding.EncodeToString(msg.Raw))
				fmt.Println("##########################")
			}

			if msg.Type.Class == stun.ClassErrorResponse && msg.Type.Method == stun.MethodRefresh {
				txdID := base64.StdEncoding.EncodeToString(msg.TransactionID[:])
				logger.Log(0, "turn refresh permission error encountered, send reset singal to turn client")
				if _, ok := stunMgsMap[txdID]; ok {
					delete(stunMgsMap, base64.StdEncoding.EncodeToString(msg.TransactionID[:]))
					continue
				}
				stunMgsMap[txdID] = struct{}{}
				resetCh <- struct{}{}

			}
		}
	}
}

func listen(serverName string, turnConn net.PacketConn) {
	logger.Log(0, "-----> Starting Turn Listener: ", turnConn.LocalAddr().String(), serverName)
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

func addPeerListener(ctx context.Context, wg *sync.WaitGroup, serverName string, resetCh chan struct{}) {
	defer wg.Done()
	defer logger.Log(0, "Closing turn conn: ", serverName)
	t, ok := config.GetCfg().GetTurnCfg(serverName)
	if !ok {
		return
	}
	turnConn, err := allocateAddr(t.Client)
	if err != nil {
		logger.Log(0, "failed to allocate addr on turn: ", err.Error())
		return
	}
	t.TurnConn = turnConn
	config.GetCfg().SetTurnCfg(serverName, t)
	go func() {
		<-ctx.Done()
		t, ok := config.GetCfg().GetTurnCfg(serverName)
		if ok {
			t.TurnConn.Close()
		}
	}()
	go listen(serverName, turnConn)
	for {
		select {
		case <-ctx.Done():
			return
		case <-resetCh:
			t, ok := config.GetCfg().GetTurnCfg(serverName)
			if !ok {
				continue
			}
			t.TurnConn.Close()
			// reallocate addr and signal all the peers
			logger.Log(0, "ReIntializing Turn Endpoint on server:", serverName)
			if t.Client == nil {
				continue
			}
			turnConn, err := allocateAddr(t.Client)
			if err != nil {
				logger.Log(0, "failed to allocate addr on turn: ", err.Error())
				return
			}
			t.TurnConn = turnConn
			config.GetCfg().SetTurnCfg(serverName, t)
			turnPeersMap := config.GetCfg().GetAllTurnPeersCfg(serverName)
			for peerKey := range turnPeersMap {
				err := SignalPeer(serverName, nm_models.Signal{
					Server:            serverName,
					FromHostPubKey:    config.GetCfg().GetDevicePubKey().String(),
					TurnRelayEndpoint: turnConn.LocalAddr().String(),
					ToHostPubKey:      peerKey,
				})
				if err != nil {
					logger.Log(0, "---> failed to signal peer: ", err.Error())
					continue
				}
				if conn, ok := config.GetCfg().GetPeer(peerKey); ok {
					logger.Log(0, "------> Resetting Peer Conn: ", peerKey)
					conn.Config.TurnConn = turnConn
					config.GetCfg().UpdatePeer(&conn)
					config.GetCfg().ResetPeer(peerKey)
				}
			}
			go listen(serverName, t.TurnConn)

		}
	}
}

func createOrRefreshPermissions(ctx context.Context, wg *sync.WaitGroup, serverName string) {
	defer wg.Done()
	turnPeersMap := config.GetCfg().GetAllTurnPeersCfg(serverName)
	ticker := time.NewTicker(time.Minute * 5)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t, ok := config.GetCfg().GetTurnCfg(serverName)
			if !ok || t.Client == nil {
				continue
			}
			for peerKey, cfg := range turnPeersMap {
				peerTurnEndpoint, err := net.ResolveUDPAddr("udp", cfg.PeerTurnAddr)
				if err != nil {
					continue
				}
				err = t.Client.CreatePermission(peerTurnEndpoint)
				if err != nil {
					logger.Log(0, "failed to refresh permission for peer: ", peerKey, err.Error())
				}
			}
		}
	}

}
