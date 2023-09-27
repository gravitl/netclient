package wireguard

import (
	"fmt"
	"net"
	"sync"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
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
	peers := config.Netclient().HostPeers
	// on freebsd, calling wgcltl.Client.ConfigureDevice() with []Peers{} causes an ioctl error --> ioctl: bad address
	if len(peers) == 0 {
		peers = nil
	}
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
	iface := netmaker.Iface // store current iface cfg before it gets overwritten
	netmaker = NCIface{
		Name:      ncutils.GetInterfaceName(),
		MTU:       host.MTU,
		Iface:     iface,
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
	IP       net.IP
	Network  net.IPNet
	AddRoute bool
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
	logger.Log(0, "adding addresses to netmaker interface")
	if err := n.ApplyAddrs(); err != nil {
		return err
	}
	if err := n.SetMTU(); err != nil {
		return fmt.Errorf("Configure set MTU %w", err)
	}
	return apply(&n.Config)
}

func SetEgressRoutes(egressRoutes []models.EgressNetworkRoutes) {
	addrs := []ifaceAddress{}
	for _, egressRoute := range egressRoutes {
		for _, egressRange := range egressRoute.EgressRanges {
			addrs = append(addrs, ifaceAddress{
				IP:      egressRoute.NodeAddr.IP,
				Network: config.ToIPNet(egressRange),
			})

		}

	}
	SetRoutes(addrs)
}

func GetInterface() *NCIface {
	return &netmaker
}

// NCIface.UpdatePeer - Updates Peers from provided PeerConfig
func (n *NCIface) UpdatePeer(p wgtypes.PeerConfig) {
	peers := []wgtypes.PeerConfig{}
	peers = append(peers, p)
	n.Config.ReplacePeers = false
	n.Config.Peers = peers
	apply(&n.Config)
}

// == private ==
type netIface interface {
	Close() error
}
