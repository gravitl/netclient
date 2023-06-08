package routes

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/networking"
	"github.com/gravitl/netmaker/logger"
	"github.com/vishvananda/netlink"
)

// SetNetmakerServerRoutes - sets necessary routes to servers through default gateway & peer endpoints
func SetNetmakerServerRoutes(defaultInterface string, server *config.Server) error {
	if !(config.GW4PeerDetected || config.GW6PeerDetected) {
		// no internet gateway --- skip
		return nil
	}
	if len(defaultInterface) == 0 || server == nil {
		return fmt.Errorf("invalid params provided when setting server routes")
	}

	defaultLink, err := netlink.LinkByName(defaultInterface)
	if err != nil {
		return err
	}

	if err = setDefaultGatewayRoute(); err != nil {
		if errors.Is(err, fmt.Errorf("no gateway found")) {
			l, err := netlink.LinkByName(ncutils.GetInterfaceName())
			if err == nil {
				_ = netlink.RouteDel(&netlink.Route{
					Dst:       nil,
					LinkIndex: l.Attrs().Index,
				})
				if err = setDefaultGatewayRoute(); err != nil {
					return err
				}
			} else {
				return err
			}
		} else {
			return err
		}
	}

	addrs := networking.GetServerAddrs(server.Name)
	for i := range addrs {
		addr := addrs[i]
		if addr.IP == nil {
			continue
		}
		if addr.IP.IsPrivate() {
			continue
		}
		if err = netlink.RouteAdd(&netlink.Route{
			Dst:       &addr,
			LinkIndex: defaultLink.Attrs().Index,
			Gw:        defaultGWRoute,
		}); err != nil && !strings.Contains(err.Error(), "file exists") {
			logger.Log(2, "failed to set route", addr.String(), "to gw", defaultGWRoute.String())
			continue
		}
		addServerRoute(addr)
		logger.Log(0, "added server route for interface", defaultInterface)
	}

	return nil
}

// SetNetmakerPeerEndpointRoutes - set peer endpoint routes through original default interface
func SetNetmakerPeerEndpointRoutes(defaultInterface string) error {
	if !(config.GW4PeerDetected || config.GW6PeerDetected) {
		// no internet gateway --- skip
		return nil
	}
	if len(defaultInterface) == 0 {
		return fmt.Errorf("no default interface provided")
	}

	_ = RemovePeerRoutes(defaultInterface) // ensure old peer routes are cleaned

	defaultLink, err := netlink.LinkByName(defaultInterface)
	if err != nil {
		return err
	}

	if err = setDefaultGatewayRoute(); err != nil {
		return err
	}

	currentPeers := config.Netclient().HostPeers
	for i := range currentPeers {
		peer := currentPeers[i]
		if peer.Endpoint == nil {
			continue
		}
		if peer.Endpoint.IP.IsPrivate() {
			continue
		}
		if !peer.Remove && peer.Endpoint != nil {
			mask := 32
			if peer.Endpoint.IP.To4() == nil && peer.Endpoint.IP.To16() != nil {
				mask = 128
			}
			_, cidr, err := net.ParseCIDR(fmt.Sprintf("%s/%d", peer.Endpoint.IP.String(), mask))
			if err == nil && cidr != nil {
				if err = netlink.RouteAdd(&netlink.Route{
					Dst:       cidr,
					LinkIndex: defaultLink.Attrs().Index,
					Gw:        defaultGWRoute,
				}); err != nil {
					continue
				}
				addPeerRoute(*cidr)
			}
		}
	}
	return nil
}

// RemoveServerRoutes - removes the server routes set by a client
func RemoveServerRoutes(defaultInterface string) error {
	if len(defaultInterface) == 0 {
		return fmt.Errorf("no default interface provided")
	}

	defaultLink, err := netlink.LinkByName(defaultInterface)
	if err != nil {
		return err
	}
	serverRouteMU.Lock()
	for i := range currentServerRoutes {
		currServerRoute := currentServerRoutes[i]
		if err = netlink.RouteDel(&netlink.Route{
			Dst:       &currServerRoute,
			LinkIndex: defaultLink.Attrs().Index,
		}); err != nil {
			continue
		}
	}
	serverRouteMU.Unlock()
	resetServerRoutes()
	return nil
}

// RemovePeerRoutes - removes the peer routes set by a client
func RemovePeerRoutes(defaultInterface string) error {
	if len(defaultInterface) == 0 {
		return fmt.Errorf("no default interface provided")
	}

	defaultLink, err := netlink.LinkByName(defaultInterface)
	if err != nil {
		return err
	}
	shouldResetPeers := true
	peerRouteMU.Lock()
	for i := range currentPeerRoutes {
		currPeerRoute := currentPeerRoutes[i]
		if err = netlink.RouteDel(&netlink.Route{
			Dst:       &currPeerRoute,
			LinkIndex: defaultLink.Attrs().Index,
		}); err != nil {
			shouldResetPeers = false
			continue
		}
	}
	peerRouteMU.Unlock()
	if shouldResetPeers {
		resetPeerRoutes()
	}
	return nil
}

// SetDefaultGateway - sets netmaker as the default gateway
func SetDefaultGateway(gwAddress *net.IPNet) error {
	if defaultGWRoute == nil {
		return fmt.Errorf("old gateway not found, can not set default gateway")
	}

	if gwAddress == nil || gwAddress.IP == nil {
		return nil
	}

	netmakerLink, err := netlink.LinkByName(ncutils.GetInterfaceName())
	if err != nil {
		return err
	}

	return netlink.RouteAdd(&netlink.Route{
		Dst:       nil,
		Gw:        gwAddress.IP,
		LinkIndex: netmakerLink.Attrs().Index,
	})
}

// RemoveDefaultGW - removes the default gateway
func RemoveDefaultGW(gwAddress *net.IPNet) error {
	if gwAddress == nil || gwAddress.IP == nil {
		return nil
	}

	src, err := netlink.LinkByName(ncutils.GetInterfaceName())
	if err != nil {
		return err
	}

	return netlink.RouteDel(&netlink.Route{
		Dst:       nil,
		Gw:        gwAddress.IP,
		LinkIndex: src.Attrs().Index,
	})
}

func setDefaultGatewayRoute() error {
	if defaultGWRoute == nil {
		gw, err := getDefaultGwIP()
		if err != nil {
			return err
		}
		if err = ensureNotNodeAddr(gw); err != nil {
			return err
		}
		defaultGWRoute = gw
	}
	return nil
}

func getDefaultGwIP() (net.IP, error) {
	routes, err := netlink.RouteGet(net.ParseIP("1.1.1.1"))
	if err != nil {
		return nil, err
	}
	if routes[0].Gw == nil {
		return nil, fmt.Errorf("no gateway found")
	}
	return routes[0].Gw, nil
}
