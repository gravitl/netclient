package networking

import (
	"context"
	"crypto/sha1"
	"fmt"
	"net"
	"sync"

	"github.com/gravitl/netclient/cache"
	"github.com/gravitl/netclient/config"
	proxy_config "github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// StartIfaceDetection - starts server to listen for best endpoints between netclients
func StartIfaceDetection(ctx context.Context, wg *sync.WaitGroup, port int) {
	defer wg.Done()
	tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		logger.Log(0, "failed to resolve iface detection address -", err.Error())
		return
	}
	l, err := net.ListenTCP("tcp", tcpAddr)
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

	buffer := make([]byte, 1024) // handle incoming data
	numBytes, err := c.Read(buffer)
	if err != nil {
		if numBytes == 0 {
			return
		}
		logger.Log(0, "error reading ping", err.Error())
		return
	}

	sendSuccess(c)
}

func sendError(c net.Conn, message string) {
	_, err := c.Write([]byte(message))
	if err != nil {
		logger.Log(0, "error writing response", err.Error())
	}
}

func storeNewPeerIface(clientPubKeyHash string, endpoint *net.UDPAddr) error {
	newIfaceValue := cache.EndpointCacheValue{ // make new entry to replace old and apply to WG peer
		Endpoint: endpoint,
	}
	err := setPeerEndpoint(clientPubKeyHash, newIfaceValue)
	if err != nil {
		return err
	}
	cache.EndpointCache.Store(clientPubKeyHash, newIfaceValue)

	return nil
}

func setPeerEndpoint(publicKeyHash string, value cache.EndpointCacheValue) error {

	currentServerPeers := config.Netclient().HostPeers
	for i := range currentServerPeers {
		currPeer := currentServerPeers[i]
		peerPubkeyHash := fmt.Sprintf("%v", sha1.Sum([]byte(currPeer.PublicKey.String())))
		if peerPubkeyHash == publicKeyHash { // filter for current peer to overwrite endpoint
			wgEndpoint := value.Endpoint
			logger.Log(0, "determined new endpoint for peer", currPeer.PublicKey.String(), "-", wgEndpoint.String())
			// check if conn is active on proxy and update
			if conn, ok := proxy_config.GetCfg().GetPeer(currPeer.PublicKey.String()); ok {
				if !conn.Config.PeerConf.Endpoint.IP.Equal(wgEndpoint.IP) {
					conn.Config.PeerConf.Endpoint = wgEndpoint
					proxy_config.GetCfg().UpdatePeer(&conn)
					proxy_config.GetCfg().ResetPeer(currPeer.PublicKey.String())
				}
			} else {
				return wireguard.UpdatePeer(&wgtypes.PeerConfig{
					PublicKey:                   currPeer.PublicKey,
					Endpoint:                    wgEndpoint,
					AllowedIPs:                  currPeer.AllowedIPs,
					PersistentKeepaliveInterval: currPeer.PersistentKeepaliveInterval,
					ReplaceAllowedIPs:           true,
				})
			}

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
