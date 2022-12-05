package peer

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/gravitl/netclient/nm-proxy/config"
	"github.com/gravitl/netclient/nm-proxy/models"
	"github.com/gravitl/netclient/nm-proxy/proxy"
	"github.com/gravitl/netclient/nm-proxy/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func AddNewPeer(wgInterface *wg.WGIface, network string, peer *wgtypes.PeerConfig, peerAddr string,
	isRelayed, isExtClient, isAttachedExtClient bool, relayTo *net.UDPAddr) error {
	if peer.PersistentKeepaliveInterval == nil {
		d := time.Second * 25
		peer.PersistentKeepaliveInterval = &d
	}
	c := models.ProxyConfig{
		LocalKey:            wgInterface.Device.PrivateKey,
		RemoteKey:           peer.PublicKey,
		WgInterface:         wgInterface,
		IsExtClient:         isExtClient,
		PeerConf:            peer,
		PersistentKeepalive: peer.PersistentKeepaliveInterval,
	}
	p := proxy.NewProxy(c)
	peerPort := models.NmProxyPort
	if isExtClient && isAttachedExtClient {
		peerPort = peer.Endpoint.Port

	}
	peerEndpointIP := peer.Endpoint.IP
	if isRelayed {
		//go server.NmProxyServer.KeepAlive(peer.Endpoint.IP.String(), common.NmProxyPort)
		if relayTo == nil {
			return errors.New("relay endpoint is nil")
		}
		peerEndpointIP = relayTo.IP
	}
	peerEndpoint, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", peerEndpointIP, peerPort))
	if err != nil {
		return err
	}
	p.Config.PeerEndpoint = peerEndpoint

	log.Printf("Starting proxy for Peer: %s\n", peer.PublicKey.String())
	err = p.Start()
	if err != nil {
		return err
	}

	connConf := models.Conn{
		Mutex:               &sync.RWMutex{},
		Key:                 peer.PublicKey,
		IsRelayed:           isRelayed,
		RelayedEndpoint:     relayTo,
		IsAttachedExtClient: isAttachedExtClient,
		Config:              p.Config,
		StopConn:            p.Close,
		ResetConn:           p.Reset,
		LocalConn:           p.LocalConn,
	}
	rPeer := models.RemotePeer{
		Interface:           wgInterface.Name,
		PeerKey:             peer.PublicKey.String(),
		IsExtClient:         isExtClient,
		Endpoint:            peerEndpoint,
		IsAttachedExtClient: isAttachedExtClient,
		LocalConn:           p.LocalConn,
	}
	config.GetGlobalCfg().SavePeer(network, &connConf)
	config.GetGlobalCfg().SavePeerByHash(&rPeer)

	if isAttachedExtClient {
		config.GetGlobalCfg().SaveExtClientInfo(&rPeer)
	}
	return nil
}

func SetPeersEndpointToProxy(network string, peers []wgtypes.PeerConfig) []wgtypes.PeerConfig {
	for _, peer := range peers {
		proxyPeer, found := config.GetGlobalCfg().GetPeer(network, peer.PublicKey.String())
		if found {
			peer.Endpoint = proxyPeer.Config.LocalConnAddr
		}
	}
	return peers
}
