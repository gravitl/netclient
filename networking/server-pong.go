package networking

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/gravitl/netclient/cache"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func InitialiseIfaceMetricsServer(ctx context.Context, wg *sync.WaitGroup) {
	nodeMap := config.GetNodes()
	if len(nodeMap) == 0 {
		return
	}
	metricPort := config.GetServer(config.CurrServer).MetricsPort
	if metricPort == 0 {
		metricPort = 51821
	}
	wg.Add(1)
	go startIfaceDetection(ctx, wg, metricPort, 4)
	wg.Add(1)
	go startIfaceDetection(ctx, wg, metricPort, 6)
}

// startIfaceDetection - starts server to listen for best endpoints between netclients
func startIfaceDetection(ctx context.Context, wg *sync.WaitGroup, port, protocal int) {
	defer wg.Done()
	tcpAddr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		logger.Log(0, "failed to resolve iface detection address -", err.Error())
		return
	}
	if protocal == 6 {
		tcpAddr, err = net.ResolveTCPAddr("tcp6", fmt.Sprintf("[::]:%d", port))
		if err != nil {
			logger.Log(0, "failed to resolve iface detection address -", err.Error())
			return
		}
	}
	network := "tcp4"
	if protocal == 6 {
		network = "tcp6"
	}
	l, err := net.ListenTCP(network, tcpAddr)
	if err != nil {
		logger.Log(0, "failed to start iface detection -", err.Error())
		return
	}
	logger.Log(0, "initialized endpoint detection on port", fmt.Sprintf("%d", port))
	go func(ctx context.Context, listener *net.TCPListener) {
		<-ctx.Done()
		logger.Log(0, "closed endpoint detection")
		l.Close()
	}(ctx, l)
	for {
		conn, err := l.Accept()
		if err != nil {
			logger.Log(1, "failed to accept connection", err.Error())
			return
		}
		go handleRequest(conn) // handle connection
	}
}

// handleRequest - handles a custom TCP ping message
// responds PONG if best connection found
func handleRequest(c net.Conn) {
	defer c.Close()
	sendSuccess(c)
}

func storeNewPeerIface(peerPubKey string, endpoint *net.UDPAddr) error {
	newIfaceValue := cache.EndpointCacheValue{ // make new entry to replace old and apply to WG peer
		Endpoint: endpoint,
	}
	err := setPeerEndpoint(peerPubKey, newIfaceValue)
	if err != nil {
		return err
	}
	cache.EndpointCache.Store(peerPubKey, newIfaceValue)

	return nil
}

func setPeerEndpoint(peerPubKey string, value cache.EndpointCacheValue) error {

	currentServerPeers := config.Netclient().HostPeers
	for i := range currentServerPeers {
		currPeer := currentServerPeers[i]
		if currPeer.PublicKey.String() == peerPubKey { // filter for current peer to overwrite endpoint
			logger.Log(0, "determined new endpoint for peer", currPeer.PublicKey.String(), "-", value.Endpoint.String())
			return wireguard.UpdatePeer(&wgtypes.PeerConfig{
				PublicKey:                   currPeer.PublicKey,
				Endpoint:                    value.Endpoint,
				AllowedIPs:                  currPeer.AllowedIPs,
				PersistentKeepaliveInterval: currPeer.PersistentKeepaliveInterval,
				ReplaceAllowedIPs:           true,
				UpdateOnly:                  true,
			})
		}

	}
	return fmt.Errorf("no peer found")
}

func sendSuccess(c net.Conn) error {
	_, err := c.Write([]byte(messages.Success)) // send success and then adjust locally to save time
	if err != nil {
		return err
	}
	return nil
}
