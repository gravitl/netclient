package routes

import (
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
	if len(defaultInterface) == 0 || server == nil {
		return fmt.Errorf("invalid params provided when setting server routes")
	}

	defaultLink, err := netlink.LinkByName(defaultInterface)
	if err != nil {
		return err
	}

	if err = setDefaultGatewayRoute(); err != nil {
		return err
	}

	addrs := networking.GetServerAddrs(server.Name)
	for i := range addrs {
		addr := addrs[i]
		if err = netlink.RouteAdd(&netlink.Route{
			Dst:       &addr,
			LinkIndex: defaultLink.Attrs().Index,
			Gw:        defaultGWRoute,
		}); err != nil && !strings.Contains(err.Error(), "file exists") {
			return err
		}
		addServerRoute(addr)
		logger.Log(0, "added server route for interface", defaultInterface)
	}

	return nil
}

// SetNetmakerPeerEndpointRoutes - set peer endpoint routes through original default interface
func SetNetmakerPeerEndpointRoutes(defaultInterface string) error {
	if len(defaultInterface) == 0 {
		return fmt.Errorf("no default interface provided")
	}

	if err := RemovePeerRoutes(defaultInterface); err != nil {
		return err
	}

	defaultLink, err := netlink.LinkByName(defaultInterface)
	if err != nil {
		return err
	}

	if err = setDefaultGatewayRoute(); err != nil {
		return err
	}

	currentPeers := config.GetHostPeerList()
	for i := range currentPeers {
		peer := currentPeers[i]
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
				}); err != nil && !strings.Contains(err.Error(), "file exists") {
					return err
				}
				addPeerRoute(*cidr)
				logger.Log(0, "added peer route for interface", defaultInterface)
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
			serverRouteMU.Unlock()
			return err
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
	peerRouteMU.Lock()
	for i := range currentPeerRoutes {
		currPeerRoute := currentPeerRoutes[i]
		if err = netlink.RouteDel(&netlink.Route{
			Dst:       &currPeerRoute,
			LinkIndex: defaultLink.Attrs().Index,
		}); err != nil {
			peerRouteMU.Unlock()
			return err
		}
	}
	peerRouteMU.Unlock()
	resetPeerRoutes()
	return nil
}

// SetDefaultGateway - sets netmaker as the default gateway
func SetDefaultGateway(gwAddress *net.IPNet) error {
	if defaultGWRoute == nil {
		return fmt.Errorf("old gateway not found, can not set default gateway")
	}

	if gwAddress == nil {
		return nil
	}

	netmakerLink, err := netlink.LinkByName(ncutils.GetInterfaceName())
	if err != nil {
		return err
	}

	if err := netlink.RouteAdd(&netlink.Route{
		Dst:       nil,
		Gw:        gwAddress.IP,
		LinkIndex: netmakerLink.Attrs().Index,
	}); err != nil {
		return err
	}
	return nil
}

// RemoveDefaultGW - removes the default gateway
func RemoveDefaultGW(gwAddress *net.IPNet) error {
	if gwAddress == nil {
		return nil
	}

	if err := netlink.RouteDel(&netlink.Route{
		Dst: nil,
		Gw:  gwAddress.IP,
	}); err != nil {
		return err
	}
	return nil
}

func setDefaultGatewayRoute() error {
	if defaultGWRoute == nil {
		routes, err := netlink.RouteGet(net.ParseIP("1.1.1.1"))
		if err != nil {
			return err
		}
		defaultGWRoute = routes[0].Gw
	}
	return nil
}
