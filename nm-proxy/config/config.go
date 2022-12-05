package config

import (
	"sync"

	"github.com/gravitl/netclient/nm-proxy/models"
)

var (
	globalConfig = &GlobalConfig{}
)

type Settings struct {
	isRelay          bool
	isIngressGateway bool
	isRelayed        bool
}

type GlobalConfig struct {
	ProxyStatus   bool
	isHostNetwork bool
	isServer      bool
	isBehindNAT   bool
	mutex         *sync.RWMutex
	ifaceConfig   wgIfaceConf
	settings      map[string]Settings
}

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

func (g *GlobalConfig) IsProxyRunning() bool {
	return g.ProxyStatus
}

func (g *GlobalConfig) Reset() {
	g = &GlobalConfig{}
}

func GetGlobalCfg() *GlobalConfig {
	return globalConfig
}

func (g *GlobalConfig) GetSettings(network string) Settings {
	return g.settings[network]
}

func (g *GlobalConfig) UpdateSettings(network string, settings Settings) {
	g.settings[network] = settings
}

func (g *GlobalConfig) DeleteSettings(network string) {
	delete(g.settings, network)
}

func (g *GlobalConfig) SetIsHostNetwork(value bool) {
	g.isHostNetwork = value
}

func (g *GlobalConfig) IsHostNetwork() bool {
	return g.isHostNetwork
}

func (g *GlobalConfig) SetRelayStatus(network string, value bool) {
	settings := g.GetSettings(network)
	settings.isRelay = value
	g.UpdateSettings(network, settings)
}

func (g *GlobalConfig) IsRelay(network string) bool {

	return g.GetSettings(network).isRelay
}

func (g *GlobalConfig) SetIngressGwStatus(network string, value bool) {
	settings := g.GetSettings(network)
	settings.isIngressGateway = value
	g.UpdateSettings(network, settings)
}

func (g *GlobalConfig) IsIngressGw(network string) bool {

	return g.GetSettings(network).isIngressGateway
}

func (g *GlobalConfig) SetRelayedStatus(network string, value bool) {
	settings := g.GetSettings(network)
	settings.isRelayed = value
	g.UpdateSettings(network, settings)
}

func (g *GlobalConfig) GetRelayedStatus(network string) bool {
	return g.GetSettings(network).isRelayed
}

func (g *GlobalConfig) SetIsServer(value bool) {
	g.isServer = value
}

func (g *GlobalConfig) IsServer() bool {
	return g.isServer
}

func (g *GlobalConfig) SetBehindNATStatus(value bool) {
	g.isBehindNAT = value
}

func (g *GlobalConfig) IsBehindNAT() bool {
	return g.isBehindNAT
}
