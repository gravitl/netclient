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
	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/nmproxy/packet"
	"github.com/gravitl/netclient/nmproxy/server"
	"github.com/gravitl/netclient/nmproxy/wg"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/metrics"
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

			go func(n int, cfg models.Proxy) {
				peerConnCfg := models.Conn{}
				if p.Config.ProxyStatus {
					peerConnCfg, _ = config.GetCfg().GetPeer(cfg.PeerPublicKey.String())
				} else {
					peerConnCfg, _ = config.GetCfg().GetNoProxyPeer(p.Config.PeerEndpoint.IP)
				}
				for server := range peerConnCfg.ServerMap {
					metric := metrics.GetMetric(server, cfg.PeerPublicKey.String())
					metric.TrafficSent += int64(n)
					metrics.UpdateMetric(server, cfg.PeerPublicKey.String(), &metric)
				}

			}(n, p.Config)

			var srcPeerKeyHash, dstPeerKeyHash string
			if p.Config.ProxyStatus {
				buf, n, srcPeerKeyHash, dstPeerKeyHash = packet.ProcessPacketBeforeSending(buf, n,
					config.GetCfg().GetDevicePubKey().String(), p.Config.PeerPublicKey.String())
				if err != nil {
					logger.Log(1, "failed to process pkt before sending: ", err.Error())
				}
			}

			logger.Log(3, fmt.Sprintf("PROXING TO REMOTE!!!---> %s >>>>> %s >>>>> %s [[ SrcPeerHash: %s, DstPeerHash: %s ]]\n",
				p.LocalConn.LocalAddr().String(), server.NmProxyServer.Server.LocalAddr().String(), p.RemoteConn.String(), srcPeerKeyHash, dstPeerKeyHash))

			_, err = server.NmProxyServer.Server.WriteToUDP(buf[:n], p.RemoteConn)
			if err != nil {
				logger.Log(1, "Failed to send to remote: ", err.Error())
			}

		}
	}

}

// Proxy.Reset - resets peer's conn
func (p *Proxy) Reset() {
	logger.Log(0, "Resetting proxy connection for peer: ", p.Config.PeerPublicKey.String())
	p.Close()
	if err := p.pullLatestConfig(); err != nil {
		logger.Log(1, "couldn't perform reset: ", p.Config.PeerPublicKey.String(), err.Error())
	}
	p.Start()
	// update peer configs
	if peer, found := config.GetCfg().GetPeer(p.Config.PeerPublicKey.String()); found {
		peer.Config = p.Config
		peer.LocalConn = p.LocalConn
		peer.ResetConn = p.Reset
		peer.StopConn = p.Close
		config.GetCfg().SavePeer(&peer)
	}
	if peer, found := config.GetCfg().GetPeerInfoByHash(models.ConvPeerKeyToHash(p.Config.PeerPublicKey.String())); found {
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
	peer, found := config.GetCfg().GetPeer(p.Config.PeerPublicKey.String())
	if found {
		p.Config.PeerEndpoint = peer.Config.PeerEndpoint
	} else {
		return errors.New("peer not found")
	}
	return nil

}

// Proxy.startMetricsThread - runs metrics loop for the peer
func (p *Proxy) startMetricsThread(wg *sync.WaitGroup) {
	ticker := time.NewTicker(metrics.MetricCollectionInterval)
	defer ticker.Stop()
	defer wg.Done()
	for {
		select {
		case <-p.Ctx.Done():
			return
		case <-ticker.C:
			peerConnCfg := models.Conn{}
			if p.Config.ProxyStatus {
				peerConnCfg, _ = config.GetCfg().GetPeer(p.Config.PeerPublicKey.String())
			} else {
				peerConnCfg, _ = config.GetCfg().GetNoProxyPeer(p.Config.PeerEndpoint.IP)
			}
			for server := range peerConnCfg.ServerMap {
				peerIDsAndAddrs, found := config.GetCfg().GetPeersIDsAndAddrs(server, peerConnCfg.Config.PeerPublicKey.String())
				if !found {
					continue
				}
				metric := metrics.GetMetric(server, p.Config.PeerPublicKey.String())
				metric.NodeConnectionStatus = make(map[string]bool)
				metric.LastRecordedLatency = 999
				connectionStatus := PeerConnectionStatus(p.Config.PeerPublicKey.String())
				for peerID := range peerIDsAndAddrs {
					metric.NodeConnectionStatus[peerID] = connectionStatus
				}
				metrics.UpdateMetric(server, p.Config.PeerPublicKey.String(), &metric)
			}

			pkt, err := packet.CreateMetricPacket(uuid.New().ID(), config.GetCfg().GetDevicePubKey(), p.Config.PeerPublicKey)
			if err == nil {
				logger.Log(3, "-----------> Sending metric packet to: ", p.RemoteConn.String())
				_, err = server.NmProxyServer.Server.WriteToUDP(pkt, p.RemoteConn)
				if err != nil {
					logger.Log(1, "Failed to send to metric pkt: ", err.Error())
				}

			} else {
				logger.Log(0, "failed to create metric pkt: ", err.Error())
			}
		}
	}
}

// Proxy.ProxyPeer proxies data from Wireguard to the remote peer and vice-versa
func (p *Proxy) ProxyPeer() {

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go p.toRemote(wg)
	wg.Add(1)
	go p.startMetricsThread(wg)
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
	peer := p.Config.PeerConf
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

// PeerConnectionStatus - get peer connection status from wireguard interface
func PeerConnectionStatus(peerPublicKey string) bool {
	ifacePeers, err := wg.GetPeers(config.GetCfg().GetIface().Name)
	if err != nil {
		return false
	}
	for _, peer := range ifacePeers {
		if peer.PublicKey.String() == peerPublicKey {
			return peer.LastHandshakeTime.After(time.Now().Add(-3*time.Minute)) && peer.ReceiveBytes+peer.TransmitBytes > 0
		}
	}
	return false
}
