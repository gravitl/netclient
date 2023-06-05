//go:build freebsd || darwin
// +build freebsd darwin

package routes

import (
	"errors"
	"fmt"
	"net"
	"os/exec"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/networking"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/net/route"
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
		return errors.New("failed to get default interface: " + err.Error())
	}
	if err = setDefaultGatewayRoute(); err != nil {
		return err
	}

	addrs := networking.GetServerAddrs(server.Name)
	for i := range addrs {
		addr := addrs[i]
		if addr.IP != nil {
			if addr.IP.To4() != nil {
				cmd := exec.Command("route", "-n", "add", "-net", "-inet", addr.String(), defaultGWRoute.String())
				if out, err := cmd.CombinedOutput(); err != nil {
					logger.Log(0, fmt.Sprintf("failed to add route with command %s - %v", cmd.String(), out))
					continue
				}
			} else {
				cmd := exec.Command("route", "-n", "add", "-net", "-inet6", addr.String(), defaultGWRoute.String())
				if out, err := cmd.CombinedOutput(); err != nil {
					logger.Log(0, fmt.Sprintf("failed to add route with command %s - %v", cmd.String(), out))
					continue
				}
			}
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

	_ = RemovePeerRoutes(defaultInterface) // best effort - ensure peer routes aren't already present

	_, err := net.InterfaceByName(defaultInterface)
	if err != nil {
		return errors.New("failed to get default interface: " + err.Error())
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
				if cidr.IP != nil {
					if cidr.IP.To4() != nil {
						cmd := exec.Command("route", "-n", "add", "-net", "-inet", cidr.String(), defaultGWRoute.String())
						if out, err := cmd.CombinedOutput(); err != nil {
							logger.Log(0, fmt.Sprintf("failed to add route with command %s - %v", cmd.String(), out))
							continue
						}
					} else {
						cmd := exec.Command("route", "-n", "add", "-net", "-inet6", cidr.String(), defaultGWRoute.String())
						if out, err := cmd.CombinedOutput(); err != nil {
							logger.Log(0, fmt.Sprintf("failed to add route with command %s - %v", cmd.String(), out))
							continue
						}
					}
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
		return errors.New("failed to get default interface: " + err.Error())
	}
	serverRouteMU.Lock()
	for i := range currentServerRoutes {
		addr := currentServerRoutes[i]
		if addr.IP != nil {
			if addr.IP.To4() != nil {
				cmd := exec.Command("route", "delete", "-net", "-inet", addr.String(), "-interface", defaultInterface)
				if out, err := cmd.CombinedOutput(); err != nil {
					logger.Log(0, fmt.Sprintf("failed to add route with command %s - %v", cmd.String(), out))
					continue
				}
			} else {
				cmd := exec.Command("route", "delete", "-net", "-inet6", addr.String(), "-interface", defaultInterface)
				if out, err := cmd.CombinedOutput(); err != nil {
					logger.Log(0, fmt.Sprintf("failed to add route with command %s - %v", cmd.String(), out))
					continue
				}
			}
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
		return errors.New("failed to get default interface: " + err.Error())
	}
	peerRouteMU.Lock()
	for i := range currentPeerRoutes {
		addr := currentPeerRoutes[i]
		if addr.IP != nil {
			if addr.IP.To4() != nil {
				cmd := exec.Command("route", "delete", "-net", "-inet", addr.String(), "-interface", defaultInterface)
				if out, err := cmd.CombinedOutput(); err != nil {
					logger.Log(0, fmt.Sprintf("failed to delete route with command %s - %v, Err: %v", cmd.String(), string(out), err))
					continue
				}
			} else {
				cmd := exec.Command("route", "delete", "-net", "-inet6", addr.String(), "-interface", defaultInterface)
				if out, err := cmd.CombinedOutput(); err != nil {
					logger.Log(0, fmt.Sprintf("failed to delete route with command %s - %v", cmd.String(), string(out)))
					continue
				}
			}
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
	cmd := exec.Command("route", "change", "default", gwAddress.IP.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Log(1, fmt.Sprintf("failed to add default gateway with command %s - %v", cmd.String(), string(out)))
		return err
	}
	return nil
}

// RemoveDefaultGW - removes the default gateway
func RemoveDefaultGW(gwAddress *net.IPNet) error {
	if defaultGWRoute == nil || (gwAddress == nil || gwAddress.IP == nil) {
		return nil
	}
	// == best effort to reset on mac ==
	cmd := exec.Command("route", "change", "default", defaultGWRoute.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Log(2, fmt.Sprintf("failed to change default gateway with command %s - %v", cmd.String(), string(out)))
		return err
	}
	cmd = exec.Command("route", "add", "default", defaultGWRoute.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Log(2, fmt.Sprintf("failed to add default gateway with command %s - %v", cmd.String(), string(out)))
		return err
	}
	return nil
}

func setDefaultGatewayRoute() error {
	if defaultGWRoute == nil {
		ip, err := getDefaultGwIP()
		if err != nil {
			return err
		}
		if err = ensureNotNodeAddr(ip); err != nil {
			return err
		}
		defaultGWRoute = ip
	}
	return nil
}

func getDefaultGwIP() (net.IP, error) {
	rib, _ := route.FetchRIB(0, route.RIBTypeRoute, 0)
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	for _, message := range messages {
		route_message := message.(*route.RouteMessage)
		addresses := route_message.Addrs
		if len(addresses) < 2 {
			continue
		}
		if gateway, ok := addresses[1].(*route.Inet4Addr); ok {
			return net.IP(gateway.IP[:]), nil
		}
	}
	return nil, errors.New("defautl gw not found")
}
