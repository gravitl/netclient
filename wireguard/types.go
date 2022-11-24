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

// NewNCIFace - creates a new Netclient interface in memory
func NewNCIface(host *config.Config, nodes config.NodeMap) *NCIface {
	firewallMark := 0
	peers := []wgtypes.PeerConfig{}
	for _, node := range nodes {
		peers = append(peers, node.Peers...)
	}
	return &NCIface{
		Name: getName(),
		MTU:  host.MTU,
		Config: wgtypes.Config{
			PrivateKey:   &host.PrivateKey,
			FirewallMark: &firewallMark,
			ListenPort:   &host.ListenPort,
			ReplacePeers: true,
			Peers:        peers,
		},
	}
}

func (n *NCIface) Close() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()
	return n.Close()
}

func (n *NCIface) Configure() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()
	return apply(nil, &n.Config)
}

// == private ==
type netIface interface {
	Close() error
}
