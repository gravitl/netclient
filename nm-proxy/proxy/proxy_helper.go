package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/c-robinson/iplib"
	"github.com/google/uuid"
	"github.com/gravitl/netclient/nm-proxy/common"
	"github.com/gravitl/netclient/nm-proxy/config"
	"github.com/gravitl/netclient/nm-proxy/metrics"
	"github.com/gravitl/netclient/nm-proxy/models"
	"github.com/gravitl/netclient/nm-proxy/packet"
	"github.com/gravitl/netclient/nm-proxy/server"
	"github.com/gravitl/netclient/nm-proxy/stun"
)

func NewProxy(config models.ProxyConfig) *Proxy {
	p := &Proxy{Config: config}
	p.Ctx, p.Cancel = context.WithCancel(context.Background())
	return p
}

func (p *Proxy) proxyToRemote(wg *sync.WaitGroup) {
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
				log.Println("ERRR READ: ", err)
				continue
			}

			// if _, found := common.GetPeer(p.Config.RemoteKey); !found {
			// 	log.Printf("Peer: %s not found in config\n", p.Config.RemoteKey)
			// 	p.Close()
			// 	return
			// }
			go func(n int, network, peerKey string) {

				metric := metrics.GetMetric(p.Config.Network, peerKey)
				metric.TrafficSent += float64(n) / (1 << 20)
				metrics.UpdateMetric(network, peerKey, &metric)

			}(n, p.Config.Network, p.Config.RemoteKey.String())

			//var srcPeerKeyHash, dstPeerKeyHash string
			if !p.Config.IsExtClient {
				buf, n, _, _ = packet.ProcessPacketBeforeSending(p.Config.Network, buf, n,
					p.Config.WgInterface.Device.PublicKey.String(), p.Config.RemoteKey.String())
				if err != nil {
					log.Println("failed to process pkt before sending: ", err)
				}
			}

			// log.Printf("PROXING TO REMOTE!!!---> %s >>>>> %s >>>>> %s [[ SrcPeerHash: %s, DstPeerHash: %s ]]\n",
			// 	p.LocalConn.LocalAddr(), server.NmProxyServer.Server.LocalAddr().String(), p.RemoteConn.String(), srcPeerKeyHash, dstPeerKeyHash)

			_, err = server.NmProxyServer.Server.WriteToUDP(buf[:n], p.RemoteConn)
			if err != nil {
				log.Println("Failed to send to remote: ", err)
			}

		}
	}

}

func (p *Proxy) Reset() {
	p.Close()
	if err := p.pullLatestConfig(); err != nil {
		log.Println("couldn't perform reset: ", err)
		return
	}
	p.Start()

}

func (p *Proxy) pullLatestConfig() error {
	peer, found := config.GetGlobalCfg().GetPeer(p.Config.Network, p.Config.RemoteKey.String())
	if found {
		p.Config.PeerEndpoint.Port = peer.Config.PeerEndpoint.Port
	} else {
		return errors.New("peer not found")
	}
	return nil

}

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
			if metric.ConnectionStatus {
				rTicker.Reset(*p.Config.PersistentKeepalive)
			}
			metric.ConnectionStatus = false
			metrics.UpdateMetric(p.Config.Network, p.Config.RemoteKey.String(), &metric)
			pkt, err := packet.CreateMetricPacket(uuid.New().ID(), p.Config.Network, p.Config.LocalKey, p.Config.RemoteKey)
			if err == nil {
				log.Printf("-----------> ##### $$$$$ SENDING METRIC PACKET TO: %s\n", p.RemoteConn.String())
				_, err = server.NmProxyServer.Server.WriteToUDP(pkt, p.RemoteConn)
				if err != nil {
					log.Println("Failed to send to metric pkt: ", err)
				}

			}
		}
	}
}

func (p *Proxy) peerUpdates(wg *sync.WaitGroup, ticker *time.Ticker) {
	defer wg.Done()
	for {
		select {
		case <-p.Ctx.Done():
			return
		case <-ticker.C:
			// send listen port packet
			var networkEncoded [packet.NetworkNameSize]byte
			b, err := base64.StdEncoding.DecodeString(p.Config.Network)
			if err != nil {
				continue
			}
			copy(networkEncoded[:], b[:packet.NetworkNameSize])
			m := &packet.ProxyUpdateMessage{
				Type:           packet.MessageProxyType,
				NetworkEncoded: networkEncoded,
				Action:         packet.UpdateListenPort,
				Sender:         p.Config.LocalKey,
				Reciever:       p.Config.RemoteKey,
				ListenPort:     uint32(stun.Host.PrivPort),
			}
			pkt, err := packet.CreateProxyUpdatePacket(m)
			if err == nil {
				log.Printf("-----------> ##### $$$$$ SENDING Proxy Update PACKET TO: %s\n", p.RemoteConn.String())
				_, err = server.NmProxyServer.Server.WriteToUDP(pkt, p.RemoteConn)
				if err != nil {
					log.Println("Failed to send to metric pkt: ", err)
				}

			}
		}
	}
}

// ProxyPeer proxies everything from Wireguard to the RemoteKey peer and vice-versa
func (p *Proxy) ProxyPeer() {
	ticker := time.NewTicker(*p.Config.PersistentKeepalive)
	defer ticker.Stop()
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go p.proxyToRemote(wg)
	// if common.BehindNAT {
	wg.Add(1)
	go p.startMetricsThread(wg, ticker)
	wg.Add(1)
	go p.peerUpdates(wg, ticker)
	// }
	wg.Wait()

}
func test(n int, buffer []byte) {
	data := buffer[:n]
	srcKeyHash := data[n-32 : n-16]
	dstKeyHash := data[n-16:]
	log.Printf("--------> TEST PACKET [ SRCKEYHASH: %x ], [ DSTKEYHASH: %x ] \n", srcKeyHash, dstKeyHash)
}

func (p *Proxy) updateEndpoint() error {
	udpAddr, err := net.ResolveUDPAddr("udp", p.LocalConn.LocalAddr().String())
	if err != nil {
		return err
	}
	// add local proxy connection as a Wireguard peer
	log.Printf("---> ####### Updating Peer:  %+v\n", p.Config.PeerConf)
	peer := *p.Config.PeerConf
	peer.Endpoint = udpAddr
	p.Config.WgInterface.UpdatePeerEndpoint(peer)

	return nil
}

func GetFreeIp(cidrAddr string, dstPort int) (string, error) {
	//ensure AddressRange is valid
	if dstPort == 0 {
		return "", errors.New("dst port should be set")
	}
	if _, _, err := net.ParseCIDR(cidrAddr); err != nil {
		log.Println("UniqueAddress encountered  an error")
		return "", err
	}
	net4 := iplib.Net4FromStr(cidrAddr)
	newAddrs := net4.FirstAddress()
	for {
		if runtime.GOOS == "darwin" {
			_, err := common.RunCmd(fmt.Sprintf("ifconfig lo0 alias %s 255.255.255.255", newAddrs.String()), true)
			if err != nil {
				log.Println("Failed to add alias: ", err)
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
			log.Println("----> GetFreeIP ERR: ", err)
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
