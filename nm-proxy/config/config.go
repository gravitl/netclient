package config

var (
	globalConfig = &GlobalConfig{}
)

type Settings struct {
}

type GlobalConfig struct {
	NetworkSettings  map[string]Settings
	isHostNetwork    bool
	isRelay          bool
	isIngressGateway bool
	isRelayed        bool
	isServer         bool
	isBehindNAT      bool
}

func GetGlobalCfg() *GlobalConfig {
	return globalConfig
}

func (g *GlobalConfig) SetIsHostNetwork(value bool) {
	g.isHostNetwork = value
}

func (g *GlobalConfig) IsHostNetwork() bool {
	return g.isHostNetwork
}

func (g *GlobalConfig) SetRelayStatus(value bool) {
	g.isRelay = value
}

func (g *GlobalConfig) IsRelay() bool {
	return g.isRelay
}

func (g *GlobalConfig) SetIngressGwStatus(value bool) {
	g.isIngressGateway = value
}

func (g *GlobalConfig) IsIngressGw() bool {
	return g.isIngressGateway
}

func (g *GlobalConfig) SetRelayedStatus(value bool) {
	g.isRelayed = value
}

func (g *GlobalConfig) GetRelayedStatus() bool {
	return g.isRelayed
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
