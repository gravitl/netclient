package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/nmproxy/packet"
	"github.com/gravitl/netclient/nmproxy/wg"
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
				return
			}

			buf, n, _, _ := packet.ProcessPacketBeforeSending(buf, n,
				config.GetCfg().GetDevicePubKey().String(), p.Config.PeerPublicKey.String())
			if err != nil {
				logger.Log(1, "failed to process pkt before sending: ", err.Error())
			}

			_, err = p.Config.TurnConn.WriteTo(buf[:n], p.RemoteConn)
			if err != nil {
				logger.Log(0, "failed to write to remote conn: ", err.Error())
				return
			}

		}
	}

}

// Proxy.Reset - resets peer's conn
func (p *Proxy) Reset() {
	logger.Log(0, "Resetting proxy connection for peer: ", p.Config.PeerPublicKey.String())
	p.Close()
	if p.Config.PeerEndpoint == nil {
		return
	}
	if err := p.pullLatestConfig(); err != nil {
		logger.Log(1, "couldn't perform reset: ", p.Config.PeerPublicKey.String(), err.Error())
	}
	p = New(p.Config)
	err := p.Start()
	if err != nil {
		logger.Log(0, "Failed to reset proxy for peer: ",
			p.Config.PeerPublicKey.String(), "Err: ", err.Error())
		return
	}
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
	config.DumpSignalChan <- struct{}{}

}

// Proxy.pullLatestConfig - pulls latest peer config
func (p *Proxy) pullLatestConfig() error {
	peer, found := config.GetCfg().GetPeer(p.Config.PeerPublicKey.String())
	if found {
		p.Config.PeerEndpoint = peer.Config.PeerEndpoint
		p.Config.TurnConn = peer.Config.TurnConn
	} else {
		return errors.New("peer not found")
	}
	return nil
}

// Proxy.ProxyPeer proxies data from Wireguard to the remote peer and vice-versa
func (p *Proxy) ProxyPeer() {

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go p.toRemote(wg)
	config.DumpSignalChan <- struct{}{}
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
	iface, err := wg.GetWgIface(ncutils.GetInterfaceName())
	if err != nil {
		return err
	}
	return iface.UpdatePeerEndpoint(peer)
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
