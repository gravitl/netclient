package routes

import (
	"fmt"
	"net"
	"sync"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
)

/*
	the routes package handles setting routes for peers and servers
	of Netclient to the original default gateway
	this enables using internet gateways and maintaining connections to the broker
*/

var (
	serverRouteMU       sync.Mutex
	peerRouteMU         sync.Mutex
	currentServerRoutes = []net.IPNet{} // list of current server IPs routed to default gateway
	currentPeerRoutes   = []net.IPNet{} // list of current peer endpoint IPs routed to default gateway
	defaultGWRoute      net.IP          // indicates the ip which traffic should be routed
)

// HasGatewayChanged - informs called if the
// gateway address has changed
func HasGatewayChanged() bool {
	if defaultGWRoute == nil {
		return false
	}
	gw, err := getDefaultGwIP()
	if err != nil {
		return false
	}

	return !gw.Equal(defaultGWRoute)
}

// CleanUp - calls for client to clean routes of peers and servers
func CleanUp(defaultInterface string, gwAddr *net.IPNet) error {
	defer func() { defaultGWRoute = nil }()

	if err := RemoveServerRoutes(defaultInterface); err != nil {
		logger.Log(0, "error occurred when removing server routes -", err.Error())
	}
	if err := RemovePeerRoutes(defaultInterface); err != nil {
		logger.Log(0, "error occurred when removing peer routes -", err.Error())
	}
	if config.GW4PeerDetected || config.GW6PeerDetected {
		if err := RemoveDefaultGW(gwAddr); err != nil {
			logger.Log(0, "error occurred when removing default GW -", err.Error())
		}
	}
	return nil
}

func addServerRoute(route net.IPNet) {
	serverRouteMU.Lock()
	defer serverRouteMU.Unlock()
	currentServerRoutes = append(currentServerRoutes, route)
}

func resetServerRoutes() {
	serverRouteMU.Lock()
	defer serverRouteMU.Unlock()
	currentServerRoutes = []net.IPNet{}
}

func addPeerRoute(route net.IPNet) {
	peerRouteMU.Lock()
	defer peerRouteMU.Unlock()
	currentPeerRoutes = append(currentPeerRoutes, route)
}

func resetPeerRoutes() {
	peerRouteMU.Lock()
	defer peerRouteMU.Unlock()
	currentPeerRoutes = []net.IPNet{}
}

func ensureNotNodeAddr(gatewayIP net.IP) error {
	currentPeers := config.Netclient().HostPeers
	for i := range currentPeers {
		peer := currentPeers[i]
		for j := range peer.AllowedIPs {
			if peer.AllowedIPs[j].String() != "0.0.0.0/0" &&
				peer.AllowedIPs[j].String() != "::/0" &&
				(peer.AllowedIPs[j].Contains(gatewayIP) ||
					peer.AllowedIPs[j].IP.Equal(gatewayIP)) {
				return fmt.Errorf("allowed ip found as gw")
			}
		}
	}

	sNodes := config.GetNodes()
	for i := range sNodes {
		node := sNodes[i]
		if node.Address.IP.Equal(gatewayIP) ||
			node.Address6.IP.Equal(gatewayIP) {
			return fmt.Errorf("assigned address found as gw")
		}
	}

	return nil
}
