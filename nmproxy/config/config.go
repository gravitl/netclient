package config

import (
	"context"
	"net"
	"sync"

	proxy "github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

var (
	// contains all the config related to proxy
	config = &Config{}
)

// Config - struct for proxy config
type Config struct {
	HostInfo                proxy.HostInfo
	ProxyStatus             bool
	isBehindNAT             bool
	mutex                   *sync.RWMutex
	ifaceConfig             wgIfaceConf
	settings                map[string]proxy.Settings // host settings per server
	metricsThreadDone       context.CancelFunc
	metricsCollectionStatus bool
	serverConn              *net.UDPConn
	fireWallStatus          bool
	fireWallClose           func()
}

// InitializeCfg - intializes all the variables and sets defaults
func InitializeCfg() {
	config = &Config{
		ProxyStatus: true,
		mutex:       &sync.RWMutex{},
		ifaceConfig: wgIfaceConf{
			iface:            nil,
			proxyPeerMap:     make(proxy.PeerConnMap),
			peerHashMap:      make(map[string]*proxy.RemotePeer),
			extSrcIpMap:      make(map[string]*proxy.RemotePeer),
			extClientWaitMap: make(map[string]*proxy.RemotePeer),
			relayPeerMap:     make(map[string]map[string]*proxy.RemotePeer),
			noProxyPeerMap:   make(proxy.PeerConnMap),
			allPeersConf:     make(map[string]models.HostPeerMap),
		},
		settings: make(map[string]proxy.Settings),
	}
}

// Config.IsProxyRunning - checks if proxy is running
func (c *Config) IsProxyRunning() bool {
	return c.ProxyStatus
}

// Config.SetHostInfo - sets host info
func (c *Config) SetHostInfo(hostInfo proxy.HostInfo) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.HostInfo = hostInfo
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

// Config.GetHostInfo - gets the host info
func (c *Config) GetHostInfo() proxy.HostInfo {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
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
func (c *Config) GetSettings(server string) proxy.Settings {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if settings, ok := c.settings[server]; ok {
		return settings
	}
	return proxy.Settings{}
}

// Config.UpdateSettings - updates network settings
func (c *Config) UpdateSettings(server string, settings proxy.Settings) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.settings[server] = settings
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
	c.mutex.RLock()
	defer c.mutex.RUnlock()
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

// Config.SetBehindNATStatus - sets NAT status for the device
func (c *Config) SetNATStatus() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.HostInfo.PrivIp != nil && proxy.IsPublicIP(c.HostInfo.PrivIp) {
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

// Config.SetFwStatus - sets the firewall status
func (c *Config) SetFwStatus(s bool) {
	c.fireWallStatus = s
}

// Config.SetFwCloseFunc - sets the firewall flush func
func (c *Config) SetFwCloseFunc(fwFlush func()) {
	c.fireWallClose = fwFlush
}

// Config.GetFwStatus - gets the firewall status
func (c *Config) GetFwStatus() bool {
	return c.fireWallStatus
}

// Config.StopFw - flushes all the firewall rules
func (c *Config) StopFw() {
	c.fireWallClose()
}
