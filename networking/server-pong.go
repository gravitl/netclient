package networking

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

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
		logger.Log(0, "error reading ping", err.Error())
		return
	}
	recvTime := time.Now().UnixMilli() // get the time received message
	var request bestIfaceMsg
	if err = json.Unmarshal(buffer[:numBytes], &request); err != nil {
		sendError(c)
		return
	}

	if len(request.Hash) > 0 { // publickeyhash + time
		pubKeyHash := request.Hash
		currenHostPubKey := config.Netclient().PublicKey.String()
		currentHostPubKeyHash := sha1.Sum([]byte(currenHostPubKey))
		if pubKeyHash == string(currentHostPubKeyHash[:]) {
			sendError(c)
			return
		}
		sentTime := request.TimeStamp
		addrInfo, err := netip.ParseAddrPort(c.RemoteAddr().String())
		if err == nil {
			endpoint := addrInfo.Addr()
			latency := time.Duration(recvTime - int64(sentTime))
			latencyTreshHold := latency + latencyVarianceThreshold
			var foundNewIface bool
			bestIface, ok := cache.EndpointCache.Load(pubKeyHash)
			if ok { // check if iface already exists
				if bestIface.(cache.EndpointCacheValue).Latency > latencyTreshHold &&
					bestIface.(cache.EndpointCacheValue).Endpoint.String() != endpoint.String() { // replace it since new one is faster
					foundNewIface = true
				}
			} else {
				foundNewIface = true
			}
			if foundNewIface { // iface not detected/calculated for peer, so set it
				if err = sendSuccess(c); err != nil {
					logger.Log(0, "failed to notify peer of new endpoint", pubKeyHash)
				} else {
					if err = storeNewPeerIface(pubKeyHash, endpoint, latency); err != nil {
						logger.Log(0, "failed to store best endpoint for peer", err.Error())
					}
					return
				}
			}
		}
	}
	sendError(c)
}

func sendError(c net.Conn) {
	_, err := c.Write([]byte(messages.Wrong))
	if err != nil {
		logger.Log(0, "error writing response", err.Error())
	}
}

func storeNewPeerIface(clientPubKeyHash string, endpoint netip.Addr, latency time.Duration) error {
	newIfaceValue := cache.EndpointCacheValue{ // make new entry to replace old and apply to WG peer
		Latency:  latency,
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

	currentServerPeers := config.GetHostPeerList()
	for i := range currentServerPeers {
		currPeer := currentServerPeers[i]
		peerPubkeyHash := fmt.Sprintf("%v", sha1.Sum([]byte(currPeer.PublicKey.String())))
		if peerPubkeyHash == publicKeyHash { // filter for current peer to overwrite endpoint
			peerPort := currPeer.Endpoint.Port
			wgEndpoint := net.UDPAddrFromAddrPort(netip.AddrPortFrom(value.Endpoint, uint16(peerPort)))
			logger.Log(0, "determined new endpoint for peer", currPeer.PublicKey.String(), "-", wgEndpoint.String())
			// check if conn is active on proxy and update
			if conn, ok := proxy_config.GetCfg().GetPeer(currPeer.PublicKey.String()); ok {
				if !conn.Config.PeerConf.Endpoint.IP.Equal(wgEndpoint.IP) {
					conn.Config.PeerConf.Endpoint = wgEndpoint
					proxy_config.GetCfg().UpdatePeer(&conn)
					conn.ResetConn()
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
