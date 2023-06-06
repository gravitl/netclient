package server

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	nc_config "github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/packet"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/metrics"
	nm_models "github.com/gravitl/netmaker/models"
)

// ProxyServer.Close - closes the proxy server
func ShutDown() {
	logger.Log(0, "Shutting down Proxy.....")

	turnCfg := config.GetCfg().GetAllTurnCfg()
	for _, tCfg := range turnCfg {
		if tCfg.Client != nil {
			tCfg.Client.Close()
		}
		if tCfg.TurnConn != nil {
			tCfg.TurnConn.Close()
		}
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

			}
		} else {
			logger.Log(1, "failed to decode metrics message: ", err.Error())
		}

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

		go func(n int, peerKey string) {

			metric := nm_models.ProxyMetric{
				TrafficRecieved: int64(n),
			}
			metrics.UpdateMetricByPeer(peerKey, &metric, true)

		}(n, peerInfo.PeerKey)
		return

	}

}
