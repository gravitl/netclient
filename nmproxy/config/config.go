package config

import (
	"context"
	"net"
	"sync"

	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netmaker/logger"
	nm_models "github.com/gravitl/netmaker/models"
)

var (
	// contains all the config related to proxy
	config = &Config{}
)

// Config - struct for proxy config
type Config struct {
	HostInfo                models.HostInfo
	ProxyStatus             bool
	isHostNetwork           bool
	isServer                bool
	isBehindNAT             bool
	mutex                   *sync.RWMutex
	ifaceConfig             wgIfaceConf
	settings                models.Settings
	RouterCfg               Router
	metricsThreadDone       context.CancelFunc
	metricsCollectionStatus bool
	serverConn              *net.UDPConn
}

// InitializeCfg - intializes all the variables and sets defaults
func InitializeCfg() {
	config = &Config{
		ProxyStatus: true,
		mutex:       &sync.RWMutex{},
		ifaceConfig: wgIfaceConf{
			iface:            nil,
			proxyPeerMap:     make(models.PeerConnMap),
			peerHashMap:      make(map[string]*models.RemotePeer),
			extSrcIpMap:      make(map[string]*models.RemotePeer),
			extClientWaitMap: make(map[string]*models.RemotePeer),
			relayPeerMap:     make(map[string]map[string]*models.RemotePeer),
			noProxyPeerMap:   make(models.PeerConnMap),
			allPeersConf:     make(map[string]nm_models.HostPeerMap),
		},
		RouterCfg: Router{
			mutex:           &sync.RWMutex{},
			IsRunning:       false,
			InboundRouting:  map[string]Routing{},
			OutboundRouting: map[string]Routing{},
		},
	}
}

// Config.IsProxyRunning - checks if proxy is running
func (c *Config) IsProxyRunning() bool {
	return c.ProxyStatus
}

// Config.SetProxyStatus - sets the proxy status
func (c *Config) SetProxyStatus(s bool) {
	c.ProxyStatus = s
}

// Config.SetHostInfo - sets host info
func (c *Config) SetHostInfo(hostInfo models.HostInfo) {
	c.HostInfo = hostInfo
}

// Config.StopMetricsCollectionThread - stops the metrics thread // only when host proxy is disabled
func (c *Config) StopMetricsCollectionThread() {
	if c.metricsThreadDone != nil {
		c.metricsThreadDone()
	}
}

// Config.GetMetricsCollectionStatus - fetchs metrics collection status when proxy is disabled for host
func (c *Config) GetMetricsCollectionStatus() bool {
	return c.metricsCollectionStatus
}

// Config.SetMetricsThreadCtx - sets the metrics thread ctx
func (c *Config) SetMetricsThreadCtx(cancelFunc context.CancelFunc) {
	c.metricsThreadDone = cancelFunc
	c.metricsCollectionStatus = true
}

// Config.GetHostInfo - gets the host info
func (c *Config) GetHostInfo() models.HostInfo {
	return c.HostInfo
}

// Reset - resets Config // to be called only when proxy is shutting down
func Reset() {
	config = &Config{}
}

// GetCfg - fethes Config
func GetCfg() *Config {
	return config
}

// Config.GetSettings - fetches host settings
func (c *Config) GetSettings() models.Settings {
	return c.settings
}

// Config.UpdateSettings - updates network settings
func (c *Config) UpdateSettings(settings models.Settings) {
	c.settings = settings
}

// Config.SetIsHostNetwork - sets host network value
func (c *Config) SetIsHostNetwork(value bool) {
	c.isHostNetwork = value
}

// Config.IsHostNetwork - checks if proxy is using host network
func (c *Config) IsHostNetwork() bool {
	return c.isHostNetwork
}

// Config.SetRelayStatus - sets host relay status
func (c *Config) SetRelayStatus(value bool) {
	settings := c.GetSettings()
	settings.IsRelay = value
	c.UpdateSettings(settings)
}

// Config.IsRelay - fetches relay status value of the host
func (c *Config) IsRelay() bool {

	return c.GetSettings().IsRelay
}

// Config.SetIngressGwStatus - sets ingressGW status
func (c *Config) SetIngressGwStatus(value bool) {
	settings := c.GetSettings()
	settings.IsIngressGateway = value
	c.UpdateSettings(settings)
}

// Config.IsIngressGw - checks if ingressGW by network
func (c *Config) IsIngressGw() bool {

	return c.GetSettings().IsIngressGateway
}

// Config.SetRelayedStatus - sets relayed status
func (c *Config) SetRelayedStatus(value bool) {
	settings := c.GetSettings()
	settings.IsRelayed = value
	c.UpdateSettings(settings)
}

// Config.GetRelayedStatus - gets relayed status
func (c *Config) GetRelayedStatus() bool {
	return c.GetSettings().IsRelayed
}

// Config.SetIsServer - sets value for IsServer
func (c *Config) SetIsServer(value bool) {
	c.isServer = value
}

// Config.IsServer - checks if proxy operating on server
func (c *Config) IsServer() bool {
	return c.isServer
}

// Config.SetBehindNATStatus - sets NAT status for the device
func (c *Config) SetNATStatus() {
	if c.HostInfo.PrivIp != nil && models.IsPublicIP(c.HostInfo.PrivIp) {
		logger.Log(1, "Host is public facing!!!")
	} else {
		c.isBehindNAT = true
	}

}

// Config.IsBehindNAT - checks if proxy is running behind NAT
func (c *Config) IsBehindNAT() bool {
	return c.isBehindNAT
}

// Config.GetServerConn - fetches the server connection
func (c *Config) GetServerConn() *net.UDPConn {
	return c.serverConn
}

// Config.SetServerConn - sets server connection
func (c *Config) SetServerConn(conn *net.UDPConn) {
	c.serverConn = conn
}
