package routes

import (
	"net"
	"sync"

	"github.com/gravitl/netclient/config"
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

// CleanUp - calls for client to clean routes of peers and servers
func CleanUp(defaultInterface string, gwAddr *net.IPNet) error {
	if err := RemoveServerRoutes(defaultInterface); err != nil {
		return err
	}
	if err := RemovePeerRoutes(defaultInterface); err != nil {
		return err
	}
	if config.GW4PeerDetected {
		return RemoveDefaultGW(gwAddr)
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
