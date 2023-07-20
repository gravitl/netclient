package server

import (
	"fmt"

	nc_config "github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/packet"
	"github.com/gravitl/netmaker/logger"
)

// ProxyServer.Close - closes the proxy server
func ShutDown() {
	logger.Log(0, "Shutting down Proxy.....")
	// clean up proxy connections
	for _, peerI := range config.GetCfg().GetAllProxyPeers() {
		peerI.Mutex.Lock()
		peerI.StopConn()
		peerI.Mutex.Unlock()

	}
	turnCfg := config.GetCfg().GetTurnCfg()
	if turnCfg == nil {
		return
	}
	if turnCfg.Client != nil {
		turnCfg.Client.Close()
	}
	if turnCfg.TurnConn != nil {
		turnCfg.TurnConn.Close()
	}
}

// ProcessIncomingPacket - process the incoming packet to the proxy
func ProcessIncomingPacket(n int, source string, buffer []byte) {
	proxyTransportMsg := true
	var err error
	var srcPeerKeyHash, dstPeerKeyHash string
	n, srcPeerKeyHash, dstPeerKeyHash, err = packet.ExtractInfo(buffer, n)
	if err != nil {
		if nc_config.Netclient().Debug {
			logger.Log(4, "proxy transport message not found: ", err.Error())
		}
		proxyTransportMsg = false
	}
	if proxyTransportMsg {
		proxyIncomingPacket(buffer[:], source, n, srcPeerKeyHash, dstPeerKeyHash)
		return
	}
}

func proxyIncomingPacket(buffer []byte, source string, n int, srcPeerKeyHash, dstPeerKeyHash string) {
	var err error
	//logger.Log(0,"--------> RECV PKT , [SRCKEYHASH: %s], SourceIP: [%s] \n", srcPeerKeyHash, source.IP.String())

	if peerInfo, ok := config.GetCfg().GetPeerInfoByHash(srcPeerKeyHash); ok {
		if nc_config.Netclient().Debug {
			logger.Log(3, fmt.Sprintf("PROXING TO LOCAL!!!---> %s <<<< %s <<<<<<<< %s   [[ RECV PKT [SRCKEYHASH: %s], [DSTKEYHASH: %s], Source: [%s] ]]\n",
				peerInfo.LocalConn.RemoteAddr(), peerInfo.LocalConn.LocalAddr(),
				source, srcPeerKeyHash, dstPeerKeyHash, source))
		}
		_, err = peerInfo.LocalConn.Write(buffer[:n])
		if err != nil {
			logger.Log(1, "Failed to proxy to Wg local interface: ", err.Error())
			//continue
		}
		return
	}

}
