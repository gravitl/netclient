package turn

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/auth"
	ncconfig "github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netmaker/logger"
	nm_models "github.com/gravitl/netmaker/models"
	"github.com/pion/logging"
	"github.com/pion/turn"
)

// ConvHostPassToHash - converts password to md5 hash
func ConvHostPassToHash(hostPass string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(hostPass)))
}

// StartClient - starts the turn client on the netclient
func StartClient(ctx context.Context, wg *sync.WaitGroup, serverName, turnDomain, turnServer string, turnPort int) {
	defer wg.Done()
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			logger.Log(0, "Failed to close connection: %s", closeErr.Error())
		}
	}()
	turnServerAddr := fmt.Sprintf("%s:%d", turnServer, turnPort)
	cfg := &turn.ClientConfig{
		STUNServerAddr: turnServerAddr,
		TURNServerAddr: turnServerAddr,
		Conn:           conn,
		Username:       ncconfig.Netclient().ID.String(),
		Password:       ConvHostPassToHash(ncconfig.Netclient().HostPass),
		Realm:          turnServer,
		Software:       "netmaker",
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	}
	client, err := turn.NewClient(cfg)
	if err != nil {
		logger.Log(0, "Failed to create TURN client: %s", err.Error())
		return
	}
	config.GetCfg().SetTurnCfg(models.TurnCfg{
		Server:    serverName,
		Domain:    turnDomain,
		ApiDomain: turnServer,
		Port:      turnPort,
		Client:    client,
	})
	<-ctx.Done()
	defer client.Close()
}

// RegisterHostWithTurn - registers the host with the given turn server
func RegisterHostWithTurn(turnApiDomain, hostID, hostPass string) error {

	api := httpclient.JSONEndpoint[nm_models.SuccessResponse, nm_models.ErrorResponse]{
		URL:    turnApiDomain,
		Route:  "/api/v1/host/register",
		Method: http.MethodPost,
		//Authorization: fmt.Sprintf("Bearer %s", op.AuthToken),
		Data: nm_models.HostTurnRegister{
			HostID:       hostID,
			HostPassHash: ConvHostPassToHash(hostPass),
		},
		Response:      nm_models.SuccessResponse{},
		ErrorResponse: nm_models.ErrorResponse{},
	}
	_, errData, err := api.GetJSON(nm_models.SuccessResponse{}, nm_models.ErrorResponse{})
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			logger.Log(1, "error server status", strconv.Itoa(errData.Code), errData.Message)
		}
		return err
	}
	return nil
}

// DeRegisterHostWithTurn - to be called when host need to be deregistered from a turn server
func DeRegisterHostWithTurn(turnApiDomain, hostID, hostPass string) error {

	api := httpclient.JSONEndpoint[nm_models.SuccessResponse, nm_models.ErrorResponse]{
		URL:    turnApiDomain,
		Route:  "/api/v1/host/deregister",
		Method: http.MethodPost,
		//Authorization: fmt.Sprintf("Bearer %s", op.AuthToken),
		Data: nm_models.HostTurnRegister{
			HostID:       hostID,
			HostPassHash: ConvHostPassToHash(hostPass),
		},
		Response:      nm_models.SuccessResponse{},
		ErrorResponse: nm_models.ErrorResponse{},
	}
	_, errData, err := api.GetJSON(nm_models.SuccessResponse{}, nm_models.ErrorResponse{})
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			logger.Log(1, "error server status", strconv.Itoa(errData.Code), errData.Message)
		}
		return err
	}
	return nil
}

func AllocateAddr(serverName string) (*net.PacketConn, error) {
	// Allocate a relay socket on the TURN server. On success, it
	// will return a net.PacketConn which represents the remote
	// socket.
	turnCfg, ok := config.GetCfg().GetTurnCfg(serverName)
	if !ok {
		return nil, errors.New("turn domain cfg not found")
	}
	relayConn, err := turnCfg.Client.Allocate()
	if err != nil {
		logger.Log(0, "Failed to allocate: ", err.Error())
		return nil, err
	}
	defer func() {
		if closeErr := relayConn.Close(); closeErr != nil {
			logger.Log(0, "Failed to close connection: ", closeErr.Error())
		}
	}()
	// Send BindingRequest to learn our external IP
	mappedAddr, err := turnCfg.Client.SendBindingRequest()
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
	return &relayConn, nil
}

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
	endpoint := httpclient.JSONEndpoint[nm_models.NodeGet, nm_models.ErrorResponse]{
		URL:           "https://" + server.API,
		Route:         "/api/nodes/",
		Method:        http.MethodGet,
		Authorization: "Bearer " + token,
		Response:      nm_models.NodeGet{},
		ErrorResponse: nm_models.ErrorResponse{},
	}
	_, errData, err := endpoint.GetJSON(nm_models.NodeGet{}, nm_models.ErrorResponse{})
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			logger.Log(0, "error getting node", strconv.Itoa(errData.Code), errData.Message)
		}
		return err
	}
	return nil
}
