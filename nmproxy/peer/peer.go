package peer

import (
	"errors"
	"net"
	"sync"

	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/nmproxy/proxy"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// AddNew - adds new peer to proxy config and starts proxying the peer
func AddNew(server string, peer wgtypes.PeerConfig, relayTo *net.UDPAddr) error {

	if peer.PersistentKeepaliveInterval == nil {
		d := models.DefaultPersistentKeepaliveInterval
		peer.PersistentKeepaliveInterval = &d
	}
	c := models.Proxy{
		PeerPublicKey: peer.PublicKey,
		PeerConf:      peer,
	}
	p := proxy.New(c)
	p.Config.PeerEndpoint = relayTo
	if t := config.GetCfg().GetTurnCfg(); t != nil && t.TurnConn != nil {
		t.Mutex.RLock()
		p.Config.TurnConn = t.TurnConn
		t.Mutex.RUnlock()
	} else {
		return errors.New("turn conn is nil")
	}
	logger.Log(0, "Starting proxy for Peer: ", peer.PublicKey.String())
	err := p.Start()
	if err != nil {
		return err
	}

	connConf := models.Conn{
		Mutex:           &sync.RWMutex{},
		Key:             peer.PublicKey,
		Config:          p.Config,
		StopConn:        p.Close,
		ResetConn:       p.Reset,
		LocalConn:       p.LocalConn,
		RelayedEndpoint: relayTo,
	}
	rPeer := models.RemotePeer{
		PeerKey:   peer.PublicKey.String(),
		Endpoint:  relayTo,
		LocalConn: p.LocalConn,
	}

	logger.Log(1, "-----> saving as proxy peer: ", connConf.Key.String())
	config.GetCfg().SavePeer(&connConf)
	config.GetCfg().SavePeerByHash(&rPeer)
	return nil
}

// SetPeersEndpointToProxy - sets peer endpoints to local addresses connected to proxy
func SetPeersEndpointToProxy(peers []wgtypes.PeerConfig) []wgtypes.PeerConfig {
	logger.Log(1, "Setting peers endpoints to proxy...")
	for i := range peers {
		proxyPeer, found := config.GetCfg().GetPeer(peers[i].PublicKey.String())
		if found {
			proxyPeer.Mutex.RLock()
			peers[i].Endpoint = proxyPeer.Config.LocalConnAddr
			proxyPeer.Mutex.RUnlock()
		}
	}
	return peers
}
