package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/gravitl/netclient/nm-proxy/config"
	"github.com/gravitl/netclient/nm-proxy/metrics"
	"github.com/gravitl/netclient/nm-proxy/models"
	"github.com/gravitl/netclient/nm-proxy/packet"
)

var (
	NmProxyServer = &ProxyServer{}
)

const (
	defaultBodySize = 65000 + packet.MessageProxySize
	defaultPort     = models.NmProxyPort
)

type Config struct {
	Port     int
	BodySize int
	IsRelay  bool
	Addr     net.Addr
}

type ProxyServer struct {
	Config Config
	Server *net.UDPConn
}

func (p *ProxyServer) Close() {
	log.Println("--------->### Shutting down Proxy.....")
	// clean up proxy connections

	for _, peerConnMap := range config.GetGlobalCfg().GetNetworkPeerMap() {
		for _, peerConnI := range peerConnMap {
			peerConnI.Mutex.Lock()
			peerConnI.StopConn()
			peerConnI.Mutex.Unlock()
		}

	}
	config.GetGlobalCfg().Reset()
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
			if err != nil || source == nil { // in future log errors?
				log.Println("RECV ERROR: ", err)
				continue
			}
			//go func(buffer []byte, source *net.UDPAddr, n int) {
			proxyTransportMsg := true
			var srcPeerKeyHash, dstPeerKeyHash, network string
			n, srcPeerKeyHash, dstPeerKeyHash, network, err = packet.ExtractInfo(buffer, n)
			if err != nil {
				log.Println("proxy transport message not found: ", err)
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
			handleMsgs(buffer, n, source)

		}
	}
}

func handleMsgs(buffer []byte, n int, source *net.UDPAddr) {

	msgType := binary.LittleEndian.Uint32(buffer[:4])
	switch packet.MessageType(msgType) {
	case packet.MessageMetricsType:
		metricMsg, err := packet.ConsumeMetricPacket(buffer[:n])
		// calc latency
		if err == nil {
			log.Printf("------->$$$$$ Recieved Metric Pkt: %+v, FROM:%s\n", metricMsg, source.String())
			_, pubKey := config.GetGlobalCfg().GetDeviceKeys()
			network := packet.DecodeNetwork(metricMsg.NetworkEncoded[:])
			if metricMsg.Sender == pubKey {
				latency := time.Now().UnixMilli() - metricMsg.TimeStamp
				metric := metrics.GetMetric(network, metricMsg.Reciever.String())
				metric.LastRecordedLatency = uint64(latency)
				metric.ConnectionStatus = true
				metric.TrafficRecieved += float64(n) / (1 << 20)
				metrics.UpdateMetric(network, metricMsg.Reciever.String(), &metric)

			} else if metricMsg.Reciever == pubKey {
				// proxy it back to the sender
				log.Println("------------> $$$ SENDING back the metric pkt to the source: ", source.String())
				_, err = NmProxyServer.Server.WriteToUDP(buffer[:n], source)
				if err != nil {
					log.Println("Failed to send metric packet to remote: ", err)
				}

				metric := metrics.GetMetric(network, metricMsg.Sender.String())
				metric.ConnectionStatus = true
				metric.TrafficRecieved += float64(n) / (1 << 20)
				metrics.UpdateMetric(network, metricMsg.Sender.String(), &metric)

			}
		}
	case packet.MessageProxyUpdateType:
		msg, err := packet.ConsumeProxyUpdateMsg(buffer[:n])
		if err == nil {
			switch msg.Action {
			case packet.UpdateListenPort:
				network := packet.DecodeNetwork(msg.NetworkEncoded[:])
				if peer, found := config.GetGlobalCfg().GetPeer(network, msg.Sender.String()); found {

					if peer.Config.PeerEndpoint.Port != int(msg.ListenPort) {
						// update peer conn
						peer.Config.PeerEndpoint.Port = int(msg.ListenPort)
						config.GetGlobalCfg().UpdatePeer(network, &peer)
						log.Println("--------> Resetting Proxy Conn For Peer ", msg.Sender.String())
						config.GetGlobalCfg().ResetPeer(network, peer.Key.String())
						return
					}

				}

			}
		}
	// consume handshake message for ext clients
	case packet.MessageInitiationType:
		priv, pub := config.GetGlobalCfg().GetDeviceKeys()
		peerKey, err := packet.ConsumeHandshakeInitiationMsg(false, buffer[:n],
			packet.NoisePublicKey(pub), packet.NoisePrivateKey(priv))
		if err != nil {
			log.Println("---------> @@@ failed to decode HS: ", err)
		} else {

			log.Println("--------> Got HandShake from peer: ", peerKey, source.String())
			if peerInfo, ok := config.GetGlobalCfg().GetExtClientWaitCfg(peerKey); ok {
				peerInfo.CommChan <- source
			}

		}
	}
}

func handleExtClients(buffer []byte, n int, source *net.UDPAddr) bool {
	isExtClient := false
	if peerInfo, ok := config.GetGlobalCfg().GetExtClientInfo(source); ok {
		_, err := peerInfo.LocalConn.Write(buffer[:n])
		if err != nil {
			log.Println("Failed to proxy to Wg local interface: ", err)
			//continue
		}
		metric := metrics.GetMetric(peerInfo.Network, peerInfo.PeerKey)
		metric.TrafficRecieved += float64(n) / (1 << 20)
		metric.ConnectionStatus = true
		metrics.UpdateMetric(peerInfo.Network, peerInfo.PeerKey, &metric)
		isExtClient = true
	}
	return isExtClient
}

func (p *ProxyServer) proxyIncomingPacket(buffer []byte, source *net.UDPAddr, n int, srcPeerKeyHash, dstPeerKeyHash, network string) {
	var err error
	//log.Printf("--------> RECV PKT , [SRCKEYHASH: %s], SourceIP: [%s] \n", srcPeerKeyHash, source.IP.String())

	if config.GetGlobalCfg().GetDeviceKeyHash() != dstPeerKeyHash && config.GetGlobalCfg().IsRelay(network) {

		log.Println("----------> Relaying######")
		// check for routing map and forward to right proxy
		if remotePeer, ok := config.GetGlobalCfg().GetRelayedPeer(srcPeerKeyHash, dstPeerKeyHash); ok {

			log.Printf("--------> Relaying PKT [ SourceIP: %s:%d ], [ SourceKeyHash: %s ], [ DstIP: %s:%d ], [ DstHashKey: %s ] \n",
				source.IP.String(), source.Port, srcPeerKeyHash, remotePeer.Endpoint.String(), remotePeer.Endpoint.Port, dstPeerKeyHash)
			_, err = p.Server.WriteToUDP(buffer[:n+packet.MessageProxySize], remotePeer.Endpoint)
			if err != nil {
				log.Println("Failed to send to remote: ", err)
			}
			return

		} else {
			if remotePeer, ok := config.GetGlobalCfg().GetRelayedPeer(dstPeerKeyHash, dstPeerKeyHash); ok {

				log.Printf("--------> Relaying BACK TO RELAYED NODE PKT [ SourceIP: %s ], [ SourceKeyHash: %s ], [ DstIP: %s ], [ DstHashKey: %s ] \n",
					source.String(), srcPeerKeyHash, remotePeer.Endpoint.String(), dstPeerKeyHash)
				_, err = p.Server.WriteToUDP(buffer[:n+packet.MessageProxySize], remotePeer.Endpoint)
				if err != nil {
					log.Println("Failed to send to remote: ", err)
				}
				return

			}

		}
	}

	if peerInfo, ok := config.GetGlobalCfg().GetPeerInfoByHash(srcPeerKeyHash); ok {

		log.Printf("PROXING TO LOCAL!!!---> %s <<<< %s <<<<<<<< %s   [[ RECV PKT [SRCKEYHASH: %s], [DSTKEYHASH: %s], SourceIP: [%s] ]]\n",
			peerInfo.LocalConn.RemoteAddr(), peerInfo.LocalConn.LocalAddr(),
			fmt.Sprintf("%s:%d", source.IP.String(), source.Port), srcPeerKeyHash, dstPeerKeyHash, source.IP.String())
		_, err = peerInfo.LocalConn.Write(buffer[:n])
		if err != nil {
			log.Println("Failed to proxy to Wg local interface: ", err)
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

// Create - creats a proxy listener
// port - port for proxy to listen on localhost
// bodySize - leave 0 to use default
// addr - the address for proxy to listen on
// forwards - indicate address to forward to, {"<address:port>",...} format
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
		//log.Println("Sending MSg: ", ip, port, err)
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
		p.Config.Port = defaultPort
	}
}

// Proxy.setDefaultBodySize - sets default body size of Proxy listener if 0
func (p *ProxyServer) setDefaultBodySize() {
	if p.Config.BodySize == 0 {
		p.Config.BodySize = defaultBodySize
	}
}
