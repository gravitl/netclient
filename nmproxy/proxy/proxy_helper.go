package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/c-robinson/iplib"
	"github.com/google/uuid"
	"github.com/gravitl/netclient/nmproxy/common"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/metrics"
	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/nmproxy/packet"
	"github.com/gravitl/netclient/nmproxy/server"
	"github.com/gravitl/netmaker/logger"
)

// New - gets new proxy config
func New(config models.Proxy) *Proxy {
	p := &Proxy{Config: config}
	p.Ctx, p.Cancel = context.WithCancel(context.Background())
	return p
}

// Proxy.toRemote - proxies data from the interface to remote peer
func (p *Proxy) toRemote(wg *sync.WaitGroup) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	buf := make([]byte, 65000)
	defer wg.Done()
	for {
		select {
		case <-p.Ctx.Done():
			return
		default:

			n, err := p.LocalConn.Read(buf)
			if err != nil {
				logger.Log(1, "error reading: ", err.Error())
				continue
			}

			// if _, found := common.GetPeer(p.Config.RemoteKey); !found {
			// 	logger.Log(0,"Peer: %s not found in config\n", p.Config.RemoteKey)
			// 	p.Close()
			// 	return
			// }
			go func(n int, network, peerKey string) {

				metric := metrics.GetMetric(p.Config.Network, peerKey)
				metric.TrafficSent += float64(n) / (1 << 20)
				metrics.UpdateMetric(network, peerKey, &metric)

			}(n, p.Config.Network, p.Config.RemoteKey.String())

			var srcPeerKeyHash, dstPeerKeyHash string
			if p.Config.ProxyStatus {
				buf, n, srcPeerKeyHash, dstPeerKeyHash = packet.ProcessPacketBeforeSending(p.Config.Network, buf, n,
					config.GetCfg().GetDevicePubKey().String(), p.Config.RemoteKey.String())
				if err != nil {
					logger.Log(0, "failed to process pkt before sending: ", err.Error())
				}
			}

			logger.Log(3, fmt.Sprintf("PROXING TO REMOTE!!!---> %s >>>>> %s >>>>> %s [[ SrcPeerHash: %s, DstPeerHash: %s ]]\n",
				p.LocalConn.LocalAddr().String(), server.NmProxyServer.Server.LocalAddr().String(), p.RemoteConn.String(), srcPeerKeyHash, dstPeerKeyHash))

			_, err = server.NmProxyServer.Server.WriteToUDP(buf[:n], p.RemoteConn)
			if err != nil {
				logger.Log(0, "Failed to send to remote: ", err.Error())
			}

		}
	}

}

// Proxy.Reset - resets peer's conn
func (p *Proxy) Reset() {
	logger.Log(0, "Resetting proxy connection for peer: ", p.Config.RemoteKey.String())
	p.Close()
	if err := p.pullLatestConfig(); err != nil {
		logger.Log(0, "couldn't perform reset: ", p.Config.RemoteKey.String(), err.Error())
	}
	p.Start()
	// update peer configs
	if peer, found := config.GetCfg().GetPeer(p.Config.Network, p.Config.RemoteKey.String()); found {
		peer.Config = p.Config
		peer.LocalConn = p.LocalConn
		peer.ResetConn = p.Reset
		peer.StopConn = p.Close
		config.GetCfg().SavePeer(p.Config.Network, &peer)
	}
	if peer, found := config.GetCfg().GetPeerInfoByHash(models.ConvPeerKeyToHash(p.Config.RemoteKey.String())); found {
		peer.LocalConn = p.LocalConn
		config.GetCfg().SavePeerByHash(&peer)
	}
	if extpeer, found := config.GetCfg().GetExtClientInfo(p.Config.PeerEndpoint); found {
		extpeer.LocalConn = p.LocalConn
		config.GetCfg().SaveExtClientInfo(&extpeer)
	}

}

// Proxy.pullLatestConfig - pulls latest peer config
func (p *Proxy) pullLatestConfig() error {
	peer, found := config.GetCfg().GetPeer(p.Config.Network, p.Config.RemoteKey.String())
	if found {
		p.Config.PeerEndpoint = peer.Config.PeerEndpoint
	} else {
		return errors.New("peer not found")
	}
	return nil

}

// Proxy.startMetricsThread - runs metrics loop for the peer
func (p *Proxy) startMetricsThread(wg *sync.WaitGroup, rTicker *time.Ticker) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	defer wg.Done()
	for {
		select {
		case <-p.Ctx.Done():
			return
		case <-ticker.C:

			metric := metrics.GetMetric(p.Config.Network, p.Config.RemoteKey.String())
			// if metric.ConnectionStatus && rTicker != nil {
			// 	rTicker.Reset(*p.Config.PersistentKeepalive)
			// }
			metric.ConnectionStatus = false
			metrics.UpdateMetric(p.Config.Network, p.Config.RemoteKey.String(), &metric)
			pkt, err := packet.CreateMetricPacket(uuid.New().ID(), p.Config.Network, p.Config.LocalKey, p.Config.RemoteKey)
			if err == nil {
				logger.Log(0, "-----------> ##### $$$$$ SENDING METRIC PACKET TO: \n", p.RemoteConn.String())
				_, err = server.NmProxyServer.Server.WriteToUDP(pkt, p.RemoteConn)
				if err != nil {
					logger.Log(1, "Failed to send to metric pkt: ", err.Error())
				}

			}
		}
	}
}

// *** NOT USED CURRENTLY ****
// Proxy.peerUpdates - sends peer updates through proxy
func (p *Proxy) peerUpdates(wg *sync.WaitGroup, ticker *time.Ticker) {
	defer wg.Done()
	for {
		select {
		case <-p.Ctx.Done():
			return
		case <-ticker.C:
			// send listen port packet
			var networkEncoded [packet.NetworkNameSize]byte
			copy(networkEncoded[:], []byte(p.Config.Network))
			if config.GetCfg().HostInfo.PubPort == 0 {
				continue
			}
			m := &packet.ProxyUpdateMessage{
				Type:           packet.MessageProxyTransportType,
				NetworkEncoded: networkEncoded,
				Action:         packet.UpdateListenPort,
				Sender:         p.Config.LocalKey,
				Reciever:       p.Config.RemoteKey,
				ListenPort:     uint32(config.GetCfg().HostInfo.PubPort),
			}
			pkt, err := packet.CreateProxyUpdatePacket(m)
			if err == nil {
				logger.Log(0, "-----------> ##### sending proxy update packet to: \n", p.RemoteConn.String())
				_, err = server.NmProxyServer.Server.WriteToUDP(pkt, p.RemoteConn)
				if err != nil {
					logger.Log(1, "Failed to send to metric pkt: ", err.Error())
				}

			}
		}
	}
}

// Proxy.ProxyPeer proxies data from Wireguard to the remote peer and vice-versa
func (p *Proxy) ProxyPeer() {
	// var ticker *time.Ticker
	// if config.GetGlobalCfg().IsBehindNAT() {
	// 	ticker = time.NewTicker(*p.Config.PersistentKeepalive)
	// 	defer ticker.Stop()
	// }

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go p.toRemote(wg)
	wg.Add(1)
	go p.startMetricsThread(wg, nil)
	// if config.GetGlobalCfg().IsBehindNAT() {
	// 	wg.Add(1)
	// 	go p.peerUpdates(wg, ticker)
	// }

	wg.Wait()

}

// Proxy.updateEndpoint - updates peer endpoint to point to proxy
func (p *Proxy) updateEndpoint() error {
	udpAddr, err := net.ResolveUDPAddr("udp", p.LocalConn.LocalAddr().String())
	if err != nil {
		return err
	}
	// add local proxy connection as a Wireguard peer
	logger.Log(1, fmt.Sprintf("---> Updating Peer Endpoint:  %+v\n", p.Config.PeerConf))
	peer := *p.Config.PeerConf
	peer.Endpoint = udpAddr
	config.GetCfg().GetIface().UpdatePeerEndpoint(peer)
	return nil
}

// GetFreeIp - gets available free ip from the cidr provided
func GetFreeIp(cidrAddr string, dstPort int) (string, error) {
	//ensure AddressRange is valid
	if dstPort == 0 {
		return "", errors.New("dst port should be set")
	}
	if _, _, err := net.ParseCIDR(cidrAddr); err != nil {
		logger.Log(1, "UniqueAddress encountered  an error")
		return "", err
	}
	net4 := iplib.Net4FromStr(cidrAddr)
	newAddrs := net4.FirstAddress()
	for {
		if runtime.GOOS == "darwin" {
			_, err := common.RunCmd(fmt.Sprintf("ifconfig lo0 alias %s 255.255.255.255", newAddrs.String()), true)
			if err != nil {
				logger.Log(1, "Failed to add alias: ", err.Error())
			}
		}

		conn, err := net.DialUDP("udp", &net.UDPAddr{
			IP:   net.ParseIP(newAddrs.String()),
			Port: models.NmProxyPort,
		}, &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: dstPort,
		})
		if err != nil {
			logger.Log(1, "----> GetFreeIP err: ", err.Error())
			if strings.Contains(err.Error(), "can't assign requested address") ||
				strings.Contains(err.Error(), "address already in use") || strings.Contains(err.Error(), "cannot assign requested address") {
				var nErr error
				newAddrs, nErr = net4.NextIP(newAddrs)
				if nErr != nil {
					return "", nErr
				}
			} else {
				return "", err
			}
		}
		if err == nil {
			conn.Close()
			return newAddrs.String(), nil
		}

	}
}
