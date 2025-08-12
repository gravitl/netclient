package wireguard

import (
	"fmt"
	"net"
	"runtime"
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
		if !node.Connected {
			continue
		}
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
	GwIP     net.IP
	IP       net.IP
	Network  net.IPNet
	AddRoute bool
	Metric   uint32
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
	err := apply(&n.Config)
	if err != nil {
		return err
	}
	return nil
}

func RemoveEgressRoutes() {
	if addrs, ok := cache.EgressRouteCache.Load(config.Netclient().Host.ID.String()); ok {
		RemoveRoutes(addrs.([]ifaceAddress))
	}

	cache.EgressRouteCache = sync.Map{}
}

func SetEgressRoutes(egressRoutes []models.EgressNetworkRoutes) {
	wgMutex.Lock()
	defer wgMutex.Unlock()
	addrs := []ifaceAddress{}

	for _, egressRoute := range egressRoutes {
		for _, egressRange := range egressRoute.EgressRangesWithMetric {
			egressRangeIPNet := config.ToIPNet(egressRange.Network)
			if egressRangeIPNet.IP != nil {
				if len(config.GetNodes()) == 1 {
					if runtime.GOOS == "linux" {
						addrs = append(addrs, ifaceAddress{
							Network: egressRangeIPNet,
							Metric:  egressRange.RouteMetric,
						})
					} else {
						if egressRoute.EgressGwAddr.IP != nil {
							addrs = append(addrs, ifaceAddress{
								Network: egressRangeIPNet,
								GwIP:    egressRoute.EgressGwAddr.IP,
								Metric:  egressRange.RouteMetric,
							})
						}
						if egressRoute.EgressGwAddr6.IP != nil {
							addrs = append(addrs, ifaceAddress{
								Network: egressRangeIPNet,
								GwIP:    egressRoute.EgressGwAddr6.IP,
								Metric:  egressRange.RouteMetric,
							})
						}
					}

					continue
				}
				if egressRangeIPNet.IP.To4() != nil && egressRoute.NodeAddr.IP != nil {
					addrs = append(addrs, ifaceAddress{
						GwIP:    egressRoute.EgressGwAddr.IP,
						IP:      egressRoute.NodeAddr.IP,
						Network: egressRangeIPNet,
						Metric:  egressRange.RouteMetric,
					})
				}
				if egressRangeIPNet.IP.To4() == nil && egressRoute.NodeAddr6.IP != nil {
					addrs = append(addrs, ifaceAddress{
						GwIP:    egressRoute.EgressGwAddr6.IP,
						IP:      egressRoute.NodeAddr6.IP,
						Network: egressRangeIPNet,
						Metric:  egressRange.RouteMetric,
					})
				}

			}

		}

	}

	if addrs1, ok := cache.EgressRouteCache.Load(config.Netclient().Host.ID.String()); ok {
		isSame := checkEgressRoutes(addrs, addrs1.([]ifaceAddress))

		if !isSame {
			RemoveRoutes(addrs1.([]ifaceAddress))
			err := SetRoutes(addrs)
			if err == nil {
				cache.EgressRouteCache.Store(config.Netclient().Host.ID.String(), addrs)
			}
		}
	} else {
		err := SetRoutes(addrs)
		if err == nil {
			cache.EgressRouteCache.Store(config.Netclient().Host.ID.String(), addrs)
		}
	}
}

func SetRoutesFromCache() {
	//egress route
	if addrs1, ok := cache.EgressRouteCache.Load(config.Netclient().Host.ID.String()); ok {
		SetRoutes(addrs1.([]ifaceAddress))
	}
	//inetGW route
	gwIp := config.Netclient().CurrGwNmIP
	if gwIp != nil {
		RestoreInternetGw()

		var igw wgtypes.PeerConfig
		for _, peer := range config.Netclient().HostPeers {
			for _, peerIP := range peer.AllowedIPs {
				if peerIP.String() == IPv4Network || peerIP.String() == IPv6Network {
					igw = peer
					break
				}
			}
		}

		SetInternetGw(igw.PublicKey.String(), gwIp)
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
		if addrs[i].IP.String() != addrs1[i].IP.String() ||
			addrs[i].Network.String() != addrs1[i].Network.String() || addrs[i].Metric != addrs1[i].Metric {
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
