package turnclient

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
	"github.com/pion/logging"
	"github.com/pion/turn"
	"golang.org/x/crypto/bcrypt"
)

var client *turn.Client
var turnInitialized bool
var AllocatedTurnAddr net.PacketConn

func Init(ctx context.Context, wg *sync.WaitGroup, turnDomain string, turnPort int) {
	if turnInitialized {
		return
	}
	logger.Log(0, "------------> STARTING TURN NETCLIENT")
	turnInitialized = true
	// TURN client won't create a local listening socket by itself.
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Panicf("Failed to close connection: %s", closeErr)
		}
	}()
	hash, err := bcrypt.GenerateFromPassword([]byte(config.Netclient().HostPass), 5)
	if err != nil {
		return
	}
	turnServerAddr := fmt.Sprintf("%s:%d", turnDomain, turnPort)
	cfg := &turn.ClientConfig{
		STUNServerAddr: turnServerAddr,
		TURNServerAddr: turnServerAddr,
		Conn:           conn,
		Username:       config.Netclient().ID.String(),
		Password:       string(hash),
		Realm:          turnDomain,
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	}

	client, err = turn.NewClient(cfg)
	if err != nil {
		log.Panicf("Failed to create TURN client: %s", err)
	}

	AllocatedTurnAddr, err = allocateRelayAddrForHost()
	if err != nil {
		log.Panic(err)
	}
	defer client.Close()
	// Start listening on the conn provided.
	err = client.Listen()
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}

}

func allocateRelayAddrForHost() (net.PacketConn, error) {
	// Allocate a relay socket on the TURN server. On success, it
	// will return a net.PacketConn which represents the remote
	// socket.
	relayConn, err := client.Allocate()
	if err != nil {
		logger.Log(0, "Failed to allocate relay addr for host: ", err.Error())
	}

	// The relayConn's local address is actually the transport
	// address assigned on the TURN server.
	log.Printf("------>$$$ relayed-address=%s", relayConn.LocalAddr().String())
	return relayConn, nil
}
