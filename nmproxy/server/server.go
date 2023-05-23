package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	nc_config "github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/nmproxy/packet"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/metrics"
	nm_models "github.com/gravitl/netmaker/models"
)

var (
	// NmProxyServer - proxy server for global access
	NmProxyServer = &ProxyServer{}
)

// Config - struct for proxy server config
type Config struct {
	Port     int
	BodySize int
}

// ProxyServer - struct for proxy server
type ProxyServer struct {
	Config Config
	Server *net.UDPConn
}

// ProxyServer.Close - closes the proxy server
func (p *ProxyServer) Close() {
	logger.Log(0, "Shutting down Proxy.....")
	// clean up proxy connections
	for _, peerI := range config.GetCfg().GetAllProxyPeers() {
		peerI.Mutex.Lock()
		peerI.StopConn()
		peerI.Mutex.Unlock()

	}
	// close metrics thread
	if config.GetCfg().GetMetricsCollectionStatus() {
		config.GetCfg().StopMetricsCollectionThread()
	}

	turnCfg := config.GetCfg().GetAllTurnCfg()
	for _, tCfg := range turnCfg {
		if tCfg.Client != nil {
			tCfg.Client.Close()
		}
		if tCfg.TurnConn != nil {
			tCfg.TurnConn.Close()
		}
	}
	// close server connection
	NmProxyServer.Server.Close()
}

// Proxy.Listen - begins listening for packets
func (p *ProxyServer) Listen(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	// Buffer with indicated body size
	buffer := make([]byte, p.Config.BodySize)
	go func() {
		<-ctx.Done()
		p.Close()
	}()
	for {
		// Read Packet
		n, source, err := p.Server.ReadFromUDP(buffer)
		if err != nil {
			logger.Log(3, "failed to read from server: ", err.Error())
			return
		}
		if source == nil {
			continue
		}
		ProcessIncomingPacket(n, source.String(), buffer)
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
	handleMsgs(buffer, n, source)
}

func handleMsgs(buffer []byte, n int, source string) {

	msgType := binary.LittleEndian.Uint32(buffer[:4])
	switch packet.MessageType(msgType) {
	case packet.MessageMetricsType:
		metricMsg, err := packet.ConsumeMetricPacket(buffer[:n])
		// calc latency
		if err == nil {
			if nc_config.Netclient().Debug {
				logger.Log(3, fmt.Sprintf("------->Recieved Metric Pkt: %+v, FROM:%s\n", metricMsg, source))
			}
			_, pubKey := config.GetCfg().GetDeviceKeys()
			if metricMsg.Sender == pubKey {
				metric := nm_models.ProxyMetric{}
				latency := time.Now().UnixMilli() - metricMsg.TimeStamp
				metric.LastRecordedLatency = uint64(latency)
				metric.TrafficRecieved = int64(n)
				metrics.UpdateMetricByPeer(metricMsg.Reciever.String(), &metric, false)
			} else if metricMsg.Reciever == pubKey {
				// proxy it back to the sender
				if nc_config.Netclient().Debug {
					logger.Log(3, "------------> $$$ sending  back the metric pkt to the source: ", source)
				}
				metricMsg.Reply = 1
				buf, err := packet.EncodePacketMetricMsg(metricMsg)
				if err == nil {
					copy(buffer[:n], buf[:])
				} else {
					logger.Log(1, "--------> failed to encode metric reply message")
				}
				sourceUdp, err := net.ResolveUDPAddr("udp", source)
				if err == nil {
					_, err = NmProxyServer.Server.WriteToUDP(buffer[:n], sourceUdp)
					if err != nil {
						logger.Log(0, "Failed to send metric packet to remote: ", err.Error())
					}
				}

			} else {
				// metric packet needs to be relayed
				if config.GetCfg().IsGlobalRelay() {
					var srcPeerKeyHash, dstPeerKeyHash string
					if metricMsg.Reply == 1 {
						dstPeerKeyHash = models.ConvPeerKeyToHash(metricMsg.Sender.String())
						srcPeerKeyHash = models.ConvPeerKeyToHash(metricMsg.Reciever.String())
					} else {
						srcPeerKeyHash = models.ConvPeerKeyToHash(metricMsg.Sender.String())
						dstPeerKeyHash = models.ConvPeerKeyToHash(metricMsg.Reciever.String())
					}
					buf, err := packet.EncodePacketMetricMsg(metricMsg)
					if err == nil {
						copy(buffer[:n], buf[:])
					} else {
						logger.Log(1, "--------> failed to encode metric relay message")
					}
					relayPacket(buffer, source, n, srcPeerKeyHash, dstPeerKeyHash)
					return
				}
			}
		} else {
			logger.Log(1, "failed to decode metrics message: ", err.Error())
		}
	case packet.MessageProxyUpdateType:
		msg, err := packet.ConsumeProxyUpdateMsg(buffer[:n])
		if err == nil {
			switch msg.Action {
			case packet.UpdateListenPort:
				if peer, found := config.GetCfg().GetPeer(msg.Sender.String()); found {
					if config.GetCfg().IsGlobalRelay() && config.GetCfg().GetDevicePubKey() != msg.Reciever {
						// update relay peer config
						if peer, found := config.GetCfg().GetRelayedPeer(models.ConvPeerKeyToHash(msg.Sender.String()),
							models.ConvPeerKeyToHash(msg.Reciever.String())); found {
							if peer.Endpoint.Port != int(msg.ListenPort) {
								config.GetCfg().UpdateListenPortForRelayedPeer(int(msg.ListenPort),
									models.ConvPeerKeyToHash(msg.Sender.String()), models.ConvPeerKeyToHash(msg.Reciever.String()))
							}

						}

					} else {
						if peer.Config.PeerEndpoint.Port != int(msg.ListenPort) {
							// update peer conn
							peer.Config.PeerEndpoint.Port = int(msg.ListenPort)
							config.GetCfg().UpdatePeer(&peer)
							logger.Log(1, "--------> Resetting Proxy Conn For Peer ", msg.Sender.String())
							config.GetCfg().ResetPeer(peer.Key.String())
							return
						}
					}

				}

			}
		}
	}
}

func relayPacket(buffer []byte, source string, n int, srcPeerKeyHash, dstPeerKeyHash string) {
	// check for routing map and relay to right proxy
	if remotePeer, ok := config.GetCfg().GetRelayedPeer(srcPeerKeyHash, dstPeerKeyHash); ok {
		if nc_config.Netclient().Debug {
			logger.Log(3, fmt.Sprintf("--------> Relaying PKT [ Source: %s ], [ SourceKeyHash: %s ], [ DstIP: %s ], [ DstHashKey: %s ] \n",
				source, srcPeerKeyHash, remotePeer.Endpoint.String(), dstPeerKeyHash))
		}
		_, err := NmProxyServer.Server.WriteToUDP(buffer[:n], remotePeer.Endpoint)
		if err != nil {
			logger.Log(1, "Failed to relay to remote: ", err.Error())
		}
		return
	}
}

func proxyIncomingPacket(buffer []byte, source string, n int, srcPeerKeyHash, dstPeerKeyHash string) {
	var err error
	//logger.Log(0,"--------> RECV PKT , [SRCKEYHASH: %s], SourceIP: [%s] \n", srcPeerKeyHash, source.IP.String())

	if config.GetCfg().GetDeviceKeyHash() != dstPeerKeyHash && config.GetCfg().IsGlobalRelay() {
		relayPacket(buffer, source, n+packet.MessageProxyTransportSize, srcPeerKeyHash, dstPeerKeyHash)
		return
	}

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

		go func(n int, peerKey string) {

			metric := nm_models.ProxyMetric{
				TrafficRecieved: int64(n),
			}
			metrics.UpdateMetricByPeer(peerKey, &metric, true)

		}(n, peerInfo.PeerKey)
		return

	}

}

// ProxyServer.CreateProxyServer - creats a proxy listener
// port - port for proxy to listen on localhost
// bodySize - leave 0 to use default
// addr - the address for proxy to listen on
func (p *ProxyServer) CreateProxyServer(port, bodySize int, addr string) (err error) {
	if p == nil {
		p = &ProxyServer{}
	}
	p.Config.Port = port
	p.Config.BodySize = bodySize
	p.setDefaults()
	p.Server, err = net.ListenUDP("udp", &net.UDPAddr{
		Port: p.Config.Port,
		IP:   net.ParseIP("0.0.0.0"),
	})
	return
}

func (p *ProxyServer) KeepAlive(ip string, port int) {
	for {
		_, _ = p.Server.WriteToUDP([]byte("hello-proxy"), &net.UDPAddr{
			IP:   net.ParseIP(ip),
			Port: port,
		})
		//logger.Log(1,"Sending MSg: ", ip, port, err)
		time.Sleep(time.Second * 5)
	}
}

// Proxy.setDefaults - sets all defaults of proxy listener
func (p *ProxyServer) setDefaults() {
	p.setDefaultBodySize()
	p.setDefaultPort()
}

// Proxy.setDefaultPort - sets default port of Proxy listener if 0
func (p *ProxyServer) setDefaultPort() {
	if p.Config.Port == 0 {
		p.Config.Port = models.NmProxyPort
	}
}

// Proxy.setDefaultBodySize - sets default body size of Proxy listener if 0
func (p *ProxyServer) setDefaultBodySize() {
	if p.Config.BodySize == 0 {
		p.Config.BodySize = packet.DefaultBodySize
	}
}
