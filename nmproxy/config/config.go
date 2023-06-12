package config

import (
	"context"
	"encoding/json"
	"os"
	"sync"

	"github.com/gravitl/netclient/nmproxy/common"
	proxyModels "github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

var (
	// contains all the config related to proxy
	config = &Config{}
	// DumpSignalChan - channel to signal dump proxy conns info
	DumpSignalChan = make(chan struct{}, 5)
)

// Config - struct for proxy config
type Config struct {
	mutex                   *sync.RWMutex
	ifaceConfig             wgIfaceConf
	metricsThreadDone       context.CancelFunc
	metricsCollectionStatus bool
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
			allPeersConf: make(map[string]models.HostPeerMap),
		},
	}
}

// Config.StopMetricsCollectionThread - stops the metrics thread // only when host proxy is disabled
func (c *Config) StopMetricsCollectionThread() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.metricsThreadDone != nil {
		c.metricsThreadDone()
		c.metricsCollectionStatus = false
	}
}

// Config.GetMetricsCollectionStatus - fetchs metrics collection status when proxy is disabled for host
func (c *Config) GetMetricsCollectionStatus() bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.metricsCollectionStatus
}

// Config.SetMetricsThreadCtx - sets the metrics thread ctx
func (c *Config) SetMetricsThreadCtx(cancelFunc context.CancelFunc) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.metricsThreadDone = cancelFunc
	c.metricsCollectionStatus = true
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
