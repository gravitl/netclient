package wireguard

import (
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/gravitl/netclient/cache"
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
			Peers:        cleanUpPeers(peers),
		},
	}
	return &netmaker
}

func cleanUpPeers(peers []wgtypes.PeerConfig) []wgtypes.PeerConfig {
	for i, peer := range peers {
		if peer.Endpoint != nil && peer.Endpoint.IP == nil {
			peers[i].Endpoint = nil
		}
	}
	return peers
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

func RemoveEgressRoutes() {
	if addrs, ok := cache.EgressRouteCache.Load(config.Netclient().Host.ID.String()); ok {
		RemoveRoutes(addrs.([]ifaceAddress))
	}

	cache.EgressRouteCache = sync.Map{}
}

func SetEgressRoutes(egressRoutes []models.EgressNetworkRoutes) {
	addrs := []ifaceAddress{}
	for _, egressRoute := range egressRoutes {
		for _, egressRange := range egressRoute.EgressRanges {
			egressRangeIPNet := config.ToIPNet(egressRange)
			if egressRangeIPNet.IP != nil {
				if egressRangeIPNet.IP.To4() != nil {
					addrs = append(addrs, ifaceAddress{
						IP:      egressRoute.NodeAddr.IP,
						Network: egressRangeIPNet,
					})
				} else if egressRoute.NodeAddr6.IP != nil {
					addrs = append(addrs, ifaceAddress{
						IP:      egressRoute.NodeAddr6.IP,
						Network: egressRangeIPNet,
					})
				}

			}

		}

	}

	if addrs1, ok := cache.EgressRouteCache.Load(config.Netclient().Host.ID.String()); ok {
		isSame := checkEgressRoutes(addrs, addrs1.([]ifaceAddress))

		if !isSame {
			RemoveRoutes(addrs1.([]ifaceAddress))
			SetRoutes(addrs)
			cache.EgressRouteCache.Store(config.Netclient().Host.ID.String(), addrs)
		}
	} else {
		SetRoutes(addrs)
		cache.EgressRouteCache.Store(config.Netclient().Host.ID.String(), addrs)
	}
}

// checkEgressRoutes - check if the addr are the same ones
func checkEgressRoutes(addrs, addrs1 []ifaceAddress) bool {
	if len(addrs) != len(addrs1) {
		return false
	}

	sort.Slice(addrs, func(i, j int) bool { return addrs[i].IP.String() < addrs[j].IP.String() })
	sort.Slice(addrs1, func(i, j int) bool { return addrs1[i].IP.String() < addrs1[j].IP.String() })

	for i := range addrs {
		if addrs[i].IP.String() != addrs1[i].IP.String() || addrs[i].Network.String() != addrs1[i].Network.String() {
			return false
		}
	}

	return true
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
