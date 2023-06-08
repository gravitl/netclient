package routes

import (
	"fmt"
	"net"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/networking"
	"github.com/gravitl/netmaker/logger"
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

	_, err := net.InterfaceByName(defaultInterface)
	if err != nil {
		return err
	}

	if err = setDefaultGatewayRoute(); err != nil {
		return err
	}

	addrs := networking.GetServerAddrs(server.Name)
	for i := range addrs {
		addr := addrs[i]
		mask := net.IP(addr.Mask)
		cmd := fmt.Sprintf("route -p add %s MASK %v %s", addr.IP.String(),
			mask,
			defaultGWRoute.String())
		_, err := ncutils.RunCmd(cmd, false)
		if err != nil {
			continue
		}
		addServerRoute(addr)
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

	_ = RemovePeerRoutes(defaultInterface) // best effort - ensure peer routes aren't already present

	_, err := net.InterfaceByName(defaultInterface)
	if err != nil {
		return err
	}

	if err = setDefaultGatewayRoute(); err != nil {
		return err
	}

	currentPeers := config.Netclient().HostPeers
	for i := range currentPeers {
		peer := currentPeers[i]
		if !peer.Remove && peer.Endpoint != nil {
			mask := 32
			if peer.Endpoint.IP.To4() == nil && peer.Endpoint.IP.To16() != nil {
				mask = 128
			}
			_, cidr, err := net.ParseCIDR(fmt.Sprintf("%s/%d", peer.Endpoint.IP.String(), mask))
			if err == nil && cidr != nil {
				mask := net.IP(cidr.Mask)
				cmd := fmt.Sprintf("route -p add %s MASK %v %s", cidr.IP.String(),
					mask,
					defaultGWRoute.String())
				_, err := ncutils.RunCmd(cmd, false)
				if err != nil {
					return err
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

	_, err := net.InterfaceByName(defaultInterface)
	if err != nil {
		return err
	}
	serverRouteMU.Lock()
	for i := range currentServerRoutes {
		currServerRoute := currentServerRoutes[i]
		cmd := fmt.Sprintf("route delete %s", currServerRoute.IP.String())
		_, err := ncutils.RunCmd(cmd, false)
		if err != nil {
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

	_, err := net.InterfaceByName(defaultInterface)
	if err != nil {
		return err
	}
	peerRouteMU.Lock()
	for i := range currentPeerRoutes {
		currPeerRoute := currentPeerRoutes[i]
		cmd := fmt.Sprintf("route delete %s", currPeerRoute.IP.String())
		_, err := ncutils.RunCmd(cmd, false)
		if err != nil {
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

	if gwAddress == nil || gwAddress.IP == nil {
		return nil
	}

	cmd := fmt.Sprintf("route add 0.0.0.0 mask 0.0.0.0 %s metric 2", gwAddress.IP.String())
	_, err := ncutils.RunCmd(cmd, false)
	if err != nil {
		return err
	}

	cmd = fmt.Sprintf("route delete 0.0.0.0 mask 0.0.0.0 %s", defaultGWRoute.String())
	_, err = ncutils.RunCmd(cmd, false)
	if err != nil {
		return err
	}

	return nil
}

// RemoveDefaultGW - removes the default gateway
func RemoveDefaultGW(gwAddress *net.IPNet) error {
	if gwAddress == nil || gwAddress.IP == nil {
		return nil
	}

	cmd := fmt.Sprintf("route add 0.0.0.0 mask 0.0.0.0 %s metric 26", defaultGWRoute.String())
	out, err := ncutils.RunCmd(cmd, false)
	if err != nil {
		logger.Log(0, "failed to add default gateway route", defaultGWRoute.String(), err.Error(), out)
		return err
	}

	cmd = fmt.Sprintf("route delete 0.0.0.0 mask 0.0.0.0 %s", gwAddress.IP.String())
	_, err = ncutils.RunCmd(cmd, false)
	if err != nil {
		logger.Log(0, "failed to remove netmaker default gateway when removing", gwAddress.IP.String())
		return err
	}

	return nil
}

func setDefaultGatewayRoute() error {
	if defaultGWRoute == nil {
		gw, err := getWindowsGateway()
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
	return getWindowsGateway()
}
