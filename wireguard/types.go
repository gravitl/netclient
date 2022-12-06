package wireguard

import (
	"net"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// NCIface - represents a Netclient network interface
type NCIface struct {
	Iface     netIface
	Name      string
	Addresses []ifaceAddress
	MTU       int
	Config    wgtypes.Config
}

var netmaker NCIface

// NewNCIFace - creates a new Netclient interface in memory
func NewNCIface(host *config.Config, nodes config.NodeMap) *NCIface {
	firewallMark := 0
	peers := []wgtypes.PeerConfig{}
	addrs := []ifaceAddress{}
	for _, node := range nodes {
		addr := ifaceAddress{}
		addr.IP = node.Address.IP
		addr.Network = node.NetworkRange
		if addr.IP == nil {
			addr.IP = node.Address6.IP
			addr.Network = node.NetworkRange6
		}
		addrs = append(addrs, addr)
		peers = append(peers, node.Peers...)
	}
	netmaker = NCIface{
		Name:      ncutils.GetInterfaceName(),
		MTU:       host.MTU,
		Addresses: addrs,
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

// ifaceAddress - interface parsed address
type ifaceAddress struct {
	IP      net.IP
	Network net.IPNet
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
