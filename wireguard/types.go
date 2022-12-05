package wireguard

import (
	"github.com/gravitl/netclient/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// NCIface - represents a Netclient network interface
type NCIface struct {
	Iface  netIface
	Name   string
	MTU    int
	Config wgtypes.Config
}

var netmaker NCIface

// NewNCIFace - creates a new Netclient interface in memory
func NewNCIface(host *config.Config, nodes config.NodeMap) *NCIface {
	firewallMark := 0
	peers := []wgtypes.PeerConfig{}
	for _, node := range nodes {
		peers = append(peers, node.Peers...)
	}
	netmaker := NCIface{
		Name: GetName(),
		MTU:  host.MTU,
		Config: wgtypes.Config{
			PrivateKey:   &host.PrivateKey,
			FirewallMark: &firewallMark,
			ListenPort:   &host.ListenPort,
			ReplacePeers: true,
			Peers:        peers,
		},
	}
	return &netmaker
}

// Close closes a netclient interface
//func (n *NCIface) Close() error {
//	wgMutex.Lock()
//	defer wgMutex.Unlock()
//	return n.Close()
//}

// Configure applies configuration to netmaker wireguard interface
func (n *NCIface) Configure() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()
	return apply(nil, &n.Config)
}

func GetInterface() *NCIface {
	return &netmaker
}

func (n *NCIface) UpdatePeer(p wgtypes.PeerConfig) {
	peers := []wgtypes.PeerConfig{}
	peers = append(peers, p)
	n.Config.ReplacePeers = false
	n.Config.Peers = peers
	apply(nil, &n.Config)
}

// == private ==
type netIface interface {
	Close() error
}
