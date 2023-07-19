package config

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/gravitl/netclient/nmproxy/common"
	proxyModels "github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netmaker/logger"
)

var (
	// contains all the config related to proxy
	config = &Config{}
	// DumpSignalChan - channel to signal dump proxy conns info
	DumpSignalChan = make(chan struct{}, 5)
)

// Config - struct for proxy config
type Config struct {
	mutex       *sync.RWMutex
	ifaceConfig wgIfaceConf
}
type proxyPeerConn struct {
	PeerPublicKey       string `json:"peer_public_key"`
	PeerEndpoint        string `json:"peer_endpoint"`
	ProxyEndpoint       string `json:"proxy_endpoint"`
	ProxyRemoteEndpoint string `json:"proxy_remote_endpoint"`
}

// InitializeCfg - intializes all the variables and sets defaults
func InitializeCfg() {
	config = &Config{
		mutex: &sync.RWMutex{},
		ifaceConfig: wgIfaceConf{
			iface:        nil,
			turnPeerMap:  make(map[string]proxyModels.TurnPeerCfg),
			proxyPeerMap: make(proxyModels.PeerConnMap),
			peerHashMap:  make(map[string]*proxyModels.RemotePeer),
		},
	}
}

// Reset - resets Config // to be called only when proxy is shutting down
func Reset() {
	config = &Config{}
}

// GetCfg - fethes Config
func GetCfg() *Config {
	return config
}

// Config.Dump - dumps the proxy peer connections information
func (c *Config) Dump() {
	peersConn := c.GetAllProxyPeers()
	proxyConns := []proxyPeerConn{}
	for peerPubKey, peerI := range peersConn {
		peerConnI := proxyPeerConn{
			PeerPublicKey: peerPubKey,
		}

		if peerI.Config.PeerConf.Endpoint != nil {
			peerConnI.PeerEndpoint = peerI.Config.PeerConf.Endpoint.String()
		}
		if peerI.Config.LocalConnAddr != nil {
			peerConnI.ProxyEndpoint = peerI.Config.LocalConnAddr.String()
		}
		if peerI.Config.RemoteConnAddr != nil {
			peerConnI.ProxyRemoteEndpoint = peerI.Config.RemoteConnAddr.String()
		}
		proxyConns = append(proxyConns, peerConnI)
	}
	out, err := json.MarshalIndent(proxyConns, "", " ")
	if err != nil {
		logger.Log(0, "failed to marshal list output: ", err.Error())
	}
	os.WriteFile(common.GetDataPath()+"proxy.json", out, os.ModePerm)
}
