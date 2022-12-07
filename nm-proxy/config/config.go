package config

import (
	"sync"

	"github.com/gravitl/netclient/nm-proxy/models"
	"github.com/gravitl/netmaker/logger"
)

var (
	// contains all the config related to proxy
	globalConfig = &GlobalConfig{}
)

// Settings - struct for network level settings
type Settings struct {
	isRelay          bool
	isIngressGateway bool
	isRelayed        bool
}

// GlobalConfig - struct for proxy config
type GlobalConfig struct {
	HostInfo      models.HostInfo
	ProxyStatus   bool
	isHostNetwork bool
	isServer      bool
	isBehindNAT   bool
	mutex         *sync.RWMutex
	ifaceConfig   wgIfaceConf
	settings      map[string]Settings
}

// InitializeGlobalCfg - intializes all the variables and sets defaults
func InitializeGlobalCfg() {
	globalConfig = &GlobalConfig{
		ProxyStatus: true,
		mutex:       &sync.RWMutex{},
		ifaceConfig: wgIfaceConf{
			iface:            nil,
			networkPeerMap:   make(map[string]models.PeerConnMap),
			peerHashMap:      make(map[string]*models.RemotePeer),
			extSrcIpMap:      make(map[string]*models.RemotePeer),
			extClientWaitMap: make(map[string]*models.RemotePeer),
			relayPeerMap:     make(map[string]map[string]*models.RemotePeer),
		},
		settings: make(map[string]Settings),
	}
}

// GlobalConfig.IsProxyRunning - checks if proxy is running
func (g *GlobalConfig) IsProxyRunning() bool {
	return g.ProxyStatus
}

// GlobalConfig.SetHostInfo - sets host info
func (g *GlobalConfig) SetHostInfo(hostInfo models.HostInfo) {
	g.HostInfo = hostInfo
}

func (g *GlobalConfig) GetHostInfo() models.HostInfo {
	return g.HostInfo
}

// Reset - resets GlobalConfig // to be called only when proxy is shutting down
func Reset() {
	globalConfig = &GlobalConfig{}
}

// GetGlobalCfg - fethes GlobalConfig
func GetGlobalCfg() *GlobalConfig {
	return globalConfig
}

// GlobalConfig.GetSettings - fetches network settings
func (g *GlobalConfig) GetSettings(network string) Settings {
	return g.settings[network]
}

// GlobalConfig.UpdateSettings - updates network settings
func (g *GlobalConfig) UpdateSettings(network string, settings Settings) {
	g.settings[network] = settings
}

// GlobalConfig.DeleteSettings - deletes network settings
func (g *GlobalConfig) DeleteSettings(network string) {
	delete(g.settings, network)
}

// GlobalConfig.SetIsHostNetwork - sets host network value
func (g *GlobalConfig) SetIsHostNetwork(value bool) {
	g.isHostNetwork = value
}

// GlobalConfig.IsHostNetwork - checks if proxy is using host network
func (g *GlobalConfig) IsHostNetwork() bool {
	return g.isHostNetwork
}

// GlobalConfig.SetRelayStatus - sets node relay status for the network
func (g *GlobalConfig) SetRelayStatus(network string, value bool) {
	settings := g.GetSettings(network)
	settings.isRelay = value
	g.UpdateSettings(network, settings)
}

// GlobalConfig.IsRelay - fetches relay status value of the node by network
func (g *GlobalConfig) IsRelay(network string) bool {

	return g.GetSettings(network).isRelay
}

// GlobalConfig.SetIngressGwStatus - sets ingressGW status
func (g *GlobalConfig) SetIngressGwStatus(network string, value bool) {
	settings := g.GetSettings(network)
	settings.isIngressGateway = value
	g.UpdateSettings(network, settings)
}

// GlobalConfig.IsIngressGw - checks if ingressGW by network
func (g *GlobalConfig) IsIngressGw(network string) bool {

	return g.GetSettings(network).isIngressGateway
}

// GlobalConfig.SetRelayedStatus - sets relayed status by network
func (g *GlobalConfig) SetRelayedStatus(network string, value bool) {
	settings := g.GetSettings(network)
	settings.isRelayed = value
	g.UpdateSettings(network, settings)
}

// GlobalConfig.GetRelayedStatus - gets relayed status
func (g *GlobalConfig) GetRelayedStatus(network string) bool {
	return g.GetSettings(network).isRelayed
}

// GlobalConfig.SetIsServer - sets value for IsServer
func (g *GlobalConfig) SetIsServer(value bool) {
	g.isServer = value
}

// GlobalConfig.IsServer - checks if proxy operating on server
func (g *GlobalConfig) IsServer() bool {
	return g.isServer
}

// GlobalConfig.SetBehindNATStatus - sets NAT status for the device
func (g *GlobalConfig) SetNATStatus() {
	if g.HostInfo.PrivIp != nil && models.IsPublicIP(g.HostInfo.PrivIp) {
		logger.Log(1, "Host is public facing!!!")
	} else {
		g.isBehindNAT = true
	}

}

// GlobalConfig.IsBehindNAT - checks if proxy is running behind NAT
func (g *GlobalConfig) IsBehindNAT() bool {
	return g.isBehindNAT
}
