package wireguard

import (
	"net"
	"sync"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/nmproxy/peer"
	"github.com/gravitl/netmaker/logger"
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
var wgMutex = sync.Mutex{} // used to mutex functions of the interface

// NewNCIFace - creates a new Netclient interface in memory
func NewNCIface(host *config.Config, nodes config.NodeMap) *NCIface {
	firewallMark := 0
	peers := config.GetHostPeerList()
	addrs := []ifaceAddress{}
	for _, node := range nodes {
		if node.Address.IP != nil {
			addrs = append(addrs, ifaceAddress{
				IP:      node.Address.IP,
				Network: node.NetworkRange,
			})
		}
		if node.Address6.IP != nil {
			addrs = append(addrs, ifaceAddress{
				IP:      node.Address6.IP,
				Network: node.NetworkRange6,
			})
		}

	}
	if config.Netclient().ProxyEnabled {
		peers = peer.SetPeersEndpointToProxy("", peers)
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
	logger.Log(3, "adding addresses to netmaker interface")
	if err := n.ApplyAddrs(); err != nil {
		return err
	}
	if err := n.SetMTU(); err != nil {
		return err
	}
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
