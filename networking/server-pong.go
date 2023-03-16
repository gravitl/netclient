package networking

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
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
	recvTime := time.Now().Unix() // get the time received message
	parts := strings.Split(string(buffer[:numBytes]), messages.Delimiter)
	if len(parts) == 3 { // publickey + time
		pubKey := parts[0]
		timeString := parts[1]
		serverName := parts[2]
		_, err := wgtypes.ParseKey(pubKey)
		if err != nil {
			sendError(c)
			return
		}
		sentTime, err := strconv.Atoi(timeString)
		if err != nil {
			sendError(c)
			return
		}
		// look up peer for this
		addrInfo := strings.Split(c.RemoteAddr().String(), ":")
		if len(addrInfo) == 2 {
			latency := time.Duration(recvTime - int64(sentTime))
			endpoint, err := netip.ParseAddr(addrInfo[0])
			if err == nil {
				var foundNewIface bool
				bestIface, ok := ifaceCache.Load(pubKey)
				if ok { // check if iface already exists
					if bestIface.(ifaceCacheValue).Latency > latency { // replace it since new one is faster
						foundNewIface = true
					}
				} else {
					foundNewIface = true
				}
				if foundNewIface { // iface not detected/calculated for peer, so set it
					if err = sendSuccess(c); err != nil {
						logger.Log(0, "failed to notify peer of new endpoint", pubKey)
					} else {
						if err = storeNewPeerIface(pubKey, serverName, endpoint, latency); err != nil {
							logger.Log(0, "failed to store best endpoint for peer", pubKey, err.Error())
						}
						return
					}
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

func storeNewPeerIface(clientPubKey, serverName string, endpoint netip.Addr, latency time.Duration) error {
	newIfaceValue := ifaceCacheValue{ // make new entry to replace old and apply to WG peer
		Latency:  latency,
		Endpoint: endpoint,
	}
	if err := setPeerEndpoint(clientPubKey, serverName, newIfaceValue); err != nil {
		return err
	}

	ifaceCache.Store(clientPubKey, newIfaceValue)
	return nil
}

func setPeerEndpoint(publicKey, serverName string, values ifaceCacheValue) error {

	currentServerPeers, ok := config.Netclient().HostPeers[serverName] // get current server peers
	if !ok {
		return fmt.Errorf("no peers found")
	}

	var peerPort = 0
	for i := range currentServerPeers {
		currPeer := currentServerPeers[i]
		if currPeer.PublicKey.String() == publicKey { // filter for current peer to overwrite endpoint
			wgEndpoint := net.UDPAddrFromAddrPort(netip.AddrPortFrom(values.Endpoint, uint16(peerPort)))
			return wireguard.UpdatePeer(&wgtypes.PeerConfig{
				PublicKey:                   currPeer.PublicKey,
				Endpoint:                    wgEndpoint,
				AllowedIPs:                  currPeer.AllowedIPs,
				PersistentKeepaliveInterval: currPeer.PersistentKeepaliveInterval,
				ReplaceAllowedIPs:           true,
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
