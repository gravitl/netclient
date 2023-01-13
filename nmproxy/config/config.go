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
	settings                map[string]models.Settings // host settings per server
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
		settings: make(map[string]models.Settings),
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
func (c *Config) GetSettings(server string) models.Settings {
	if settings, ok := c.settings[server]; ok {
		return settings
	}
	return models.Settings{}
}

// Config.UpdateSettings - updates network settings
func (c *Config) UpdateSettings(server string, settings models.Settings) {
	c.settings[server] = settings
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
func (c *Config) SetRelayStatus(server string, value bool) {
	settings := c.GetSettings(server)
	settings.IsRelay = value
	c.UpdateSettings(server, settings)
}

// Config.IsRelay - fetches relay status value of the host
func (c *Config) IsRelay(server string) bool {
	return c.GetSettings(server).IsRelay
}

// Config.IsGlobalRelay - checks if host relay globally
func (c *Config) IsGlobalRelay() bool {
	for _, settings := range c.settings {
		if settings.IsRelay {
			return true
		}
	}
	return false
}

// Config.SetIngressGwStatus - sets ingressGW status
func (c *Config) SetIngressGwStatus(server string, value bool) {
	settings := c.GetSettings(server)
	settings.IsIngressGateway = value
	c.UpdateSettings(server, settings)
}

// Config.IsIngressGw - checks if ingressGW by server
func (c *Config) IsIngressGw(server string) bool {

	return c.GetSettings(server).IsIngressGateway
}

// Config.SetRelayedStatus - sets relayed status
func (c *Config) SetRelayedStatus(server string, value bool) {
	settings := c.GetSettings(server)
	settings.IsRelayed = value
	c.UpdateSettings(server, settings)
}

// Config.GetRelayedStatus - gets relayed status
func (c *Config) GetRelayedStatus(server string) bool {
	return c.GetSettings(server).IsRelayed
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
