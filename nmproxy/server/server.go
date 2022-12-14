package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/metrics"
	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/nmproxy/packet"
	"github.com/gravitl/netmaker/logger"
)

var (
	// NmProxyServer - proxy server for global access
	NmProxyServer = &ProxyServer{}
)

const (
	// constant for proxy server buffer size
	defaultBodySize = 65000 + packet.MessageProxyTransportSize
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
	logger.Log(1, "--------->### Shutting down Proxy.....")
	// clean up proxy connections

	for _, peerConnMap := range config.GetCfg().GetNetworkPeerMap() {
		for _, peerConnI := range peerConnMap {
			peerConnI.Mutex.Lock()
			peerConnI.StopConn()
			peerConnI.Mutex.Unlock()
		}

	}
	config.Reset()
	// close server connection
	NmProxyServer.Server.Close()
}

// Proxy.Listen - begins listening for packets
func (p *ProxyServer) Listen(ctx context.Context) {

	// Buffer with indicated body size
	buffer := make([]byte, p.Config.BodySize)
	for {

		select {
		case <-ctx.Done():
			p.Close()
			return
		default:
			// Read Packet

			n, source, err := p.Server.ReadFromUDP(buffer)
			if err != nil || source == nil {
				logger.Log(3, "failed to read from server: ", err.Error())
				continue
			}

			if !handleNoProxyPeer(buffer[:], n, source) {
				proxyTransportMsg := true
				var srcPeerKeyHash, dstPeerKeyHash, network string
				n, srcPeerKeyHash, dstPeerKeyHash, network, err = packet.ExtractInfo(buffer, n)
				if err != nil {
					logger.Log(2, "proxy transport message not found: ", err.Error())
					proxyTransportMsg = false
				}
				if proxyTransportMsg {
					p.proxyIncomingPacket(buffer[:], source, n, srcPeerKeyHash, dstPeerKeyHash, network)
					continue
				} else {
					// unknown peer to proxy -> check if extclient and handle it
					if handleExtClients(buffer[:], n, source) {
						continue
					}

				}
			}

			p.handleMsgs(buffer, n, source)

		}
	}
}

func (p *ProxyServer) handleMsgs(buffer []byte, n int, source *net.UDPAddr) {

	msgType := binary.LittleEndian.Uint32(buffer[:4])
	switch packet.MessageType(msgType) {
	case packet.MessageMetricsType:
		metricMsg, err := packet.ConsumeMetricPacket(buffer[:n])
		// calc latency
		if err == nil {
			logger.Log(3, fmt.Sprintf("------->Recieved Metric Pkt: %+v, FROM:%s\n", metricMsg, source.String()))
			_, pubKey := config.GetCfg().GetDeviceKeys()
			network := packet.DecodeNetwork(metricMsg.NetworkEncoded)
			if metricMsg.Sender == pubKey {
				latency := time.Now().UnixMilli() - metricMsg.TimeStamp
				metric := metrics.GetMetric(network, metricMsg.Reciever.String())
				metric.LastRecordedLatency = uint64(latency)
				metric.ConnectionStatus = true
				metric.TrafficRecieved += float64(n) / (1 << 20)
				metrics.UpdateMetric(network, metricMsg.Reciever.String(), &metric)

			} else if metricMsg.Reciever == pubKey {
				// proxy it back to the sender
				logger.Log(3, "------------> $$$ sending  back the metric pkt to the source: ", source.String())
				metricMsg.Reply = 1
				buf, err := packet.EncodePacketMetricMsg(metricMsg)
				if err == nil {
					copy(buffer[:n], buf[:])
				} else {
					logger.Log(1, "--------> failed to encode metric reply message")
				}
				_, err = NmProxyServer.Server.WriteToUDP(buffer[:n], source)
				if err != nil {
					logger.Log(0, "Failed to send metric packet to remote: ", err.Error())
				}

				metric := metrics.GetMetric(network, metricMsg.Sender.String())
				metric.ConnectionStatus = true
				metric.TrafficRecieved += float64(n) / (1 << 20)
				metrics.UpdateMetric(network, metricMsg.Sender.String(), &metric)

			} else {
				// metric packet needs to be relayed
				if config.GetCfg().IsRelay(network) {
					var srcPeerKeyHash, dstPeerKeyHash string
					if metricMsg.Reply == 1 {
						dstPeerKeyHash = models.ConvPeerKeyToHash(metricMsg.Sender.String())
						srcPeerKeyHash = models.ConvPeerKeyToHash(metricMsg.Reciever.String())
					} else {
						srcPeerKeyHash = models.ConvPeerKeyToHash(metricMsg.Sender.String())
						dstPeerKeyHash = models.ConvPeerKeyToHash(metricMsg.Reciever.String())
					}
					p.relayPacket(buffer, source, n, srcPeerKeyHash, dstPeerKeyHash)
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
				network := packet.DecodeNetwork(msg.NetworkEncoded)
				if peer, found := config.GetCfg().GetPeer(network, msg.Sender.String()); found {
					if config.GetCfg().IsRelay(network) && config.GetCfg().GetDevicePubKey() != msg.Reciever {
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
							config.GetCfg().UpdatePeer(network, &peer)
							logger.Log(1, "--------> Resetting Proxy Conn For Peer ", msg.Sender.String())
							config.GetCfg().ResetPeer(network, peer.Key.String())
							return
						}
					}

				}

			}
		}
	// consume handshake message for ext clients
	case packet.MessageInitiationType:
		priv, pub := config.GetCfg().GetDeviceKeys()
		peerKey, err := packet.ConsumeHandshakeInitiationMsg(false, buffer[:n],
			packet.NoisePublicKey(pub), packet.NoisePrivateKey(priv))
		if err != nil {
			logger.Log(1, "---------> @@@ failed to decode HS: ", err.Error())
		} else {

			logger.Log(1, "--------> Got HandShake from peer: ", peerKey, source.String())
			if peerInfo, ok := config.GetCfg().GetExtClientWaitCfg(peerKey); ok {
				peerInfo.CommChan <- source
			} else {
				// check if endpoint needs to be updated for the extclient
				if peerInfoHash, found := config.GetCfg().GetPeerInfoByHash(models.ConvPeerKeyToHash(peerKey)); found {
					if peerInfoHash.Endpoint.String() != source.String() {
						// update ext client endpoint
						if extPeer, found := config.GetCfg().GetExtClientInfo(peerInfoHash.Endpoint); found {
							logger.Log(1, "----> Updating ExtPeer endpoint from: ", extPeer.Endpoint.String(), " to: ", source.String())
							config.GetCfg().DeleteExtClientInfo(extPeer.Endpoint)
							peerInfoHash.Endpoint = source
							extPeer.Endpoint = source
							config.GetCfg().SavePeerByHash(&peerInfoHash)
							config.GetCfg().SaveExtClientInfo(&extPeer)
							if peerInfo, found := config.GetCfg().GetPeer(peerInfoHash.Network, peerKey); found {
								peerInfo.Config.PeerEndpoint = source
								config.GetCfg().SavePeer(peerInfoHash.Network, &peerInfo)
								// reset connection for the ext peer
								peerInfo.ResetConn()
							}

						}

					}
				}
			}

		}
	}
}

func handleExtClients(buffer []byte, n int, source *net.UDPAddr) bool {
	isExtClient := false
	if peerInfo, ok := config.GetCfg().GetExtClientInfo(source); ok {
		_, err := peerInfo.LocalConn.Write(buffer[:n])
		if err != nil {
			logger.Log(1, "Failed to proxy to Wg local interface: ", err.Error())
			//continue
		}
		metric := metrics.GetMetric(peerInfo.Network, peerInfo.PeerKey)
		metric.TrafficRecieved += float64(n) / (1 << 20)
		metrics.UpdateMetric(peerInfo.Network, peerInfo.PeerKey, &metric)
		isExtClient = true
	}
	return isExtClient
}

func handleNoProxyPeer(buffer []byte, n int, source *net.UDPAddr) bool {
	fromNoProxyPeer := false
	if peerInfo, found := config.GetCfg().GetNoProxyPeer(source.IP); found {
		logger.Log(0, fmt.Sprintf("PROXING No Proxy Peer TO LOCAL!!!---> %s <<<< %s <<<<<<<< %s   [[ SourceIP: [%s] ]]\n",
			peerInfo.LocalConn.RemoteAddr(), peerInfo.LocalConn.LocalAddr(),
			fmt.Sprintf("%s:%d", source.IP.String(), source.Port), source.IP.String()))
		_, err := peerInfo.LocalConn.Write(buffer[:n])
		if err != nil {
			logger.Log(1, "Failed to proxy to Wg local interface: ", err.Error())
		}
		metric := metrics.GetMetric(peerInfo.Config.Network, peerInfo.Key.String())
		metric.TrafficRecieved += float64(n) / (1 << 20)
		metrics.UpdateMetric(peerInfo.Config.Network, peerInfo.Key.String(), &metric)
		fromNoProxyPeer = true
	}
	return fromNoProxyPeer
}

func (p *ProxyServer) relayPacket(buffer []byte, source *net.UDPAddr, n int, srcPeerKeyHash, dstPeerKeyHash string) {
	// check for routing map and relay to right proxy
	if remotePeer, ok := config.GetCfg().GetRelayedPeer(srcPeerKeyHash, dstPeerKeyHash); ok {

		logger.Log(3, fmt.Sprintf("--------> Relaying PKT [ SourceIP: %s:%d ], [ SourceKeyHash: %s ], [ DstIP: %s:%d ], [ DstHashKey: %s ] \n",
			source.IP.String(), source.Port, srcPeerKeyHash, remotePeer.Endpoint.String(), remotePeer.Endpoint.Port, dstPeerKeyHash))
		_, err := p.Server.WriteToUDP(buffer[:n+packet.MessageProxyTransportSize], remotePeer.Endpoint)
		if err != nil {
			logger.Log(1, "Failed to relay to remote: ", err.Error())
		}
		return

	}
}

func (p *ProxyServer) proxyIncomingPacket(buffer []byte, source *net.UDPAddr, n int, srcPeerKeyHash, dstPeerKeyHash, network string) {
	var err error
	//logger.Log(0,"--------> RECV PKT , [SRCKEYHASH: %s], SourceIP: [%s] \n", srcPeerKeyHash, source.IP.String())

	if config.GetCfg().GetDeviceKeyHash() != dstPeerKeyHash && config.GetCfg().IsRelay(network) {
		p.relayPacket(buffer, source, n, srcPeerKeyHash, dstPeerKeyHash)
		return
	}

	if peerInfo, ok := config.GetCfg().GetPeerInfoByHash(srcPeerKeyHash); ok {

		logger.Log(0, fmt.Sprintf("PROXING TO LOCAL!!!---> %s <<<< %s <<<<<<<< %s   [[ RECV PKT [SRCKEYHASH: %s], [DSTKEYHASH: %s], SourceIP: [%s] ]]\n",
			peerInfo.LocalConn.RemoteAddr(), peerInfo.LocalConn.LocalAddr(),
			fmt.Sprintf("%s:%d", source.IP.String(), source.Port), srcPeerKeyHash, dstPeerKeyHash, source.IP.String()))
		_, err = peerInfo.LocalConn.Write(buffer[:n])
		if err != nil {
			logger.Log(1, "Failed to proxy to Wg local interface: ", err.Error())
			//continue
		}

		go func(n int, network, peerKey string) {

			metric := metrics.GetMetric(network, peerKey)
			metric.TrafficRecieved += float64(n) / (1 << 20)
			metric.ConnectionStatus = true
			metrics.UpdateMetric(network, peerKey, &metric)

		}(n, peerInfo.Network, peerInfo.PeerKey)
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
		IP:   net.ParseIP(addr),
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
		p.Config.BodySize = defaultBodySize
	}
}
