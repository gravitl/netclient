package uiapi

import (
	"strings"

	"github.com/gravitl/netclient/config"
)

// getCurrServerName returns the active server context only.
// Do not fall back to the sole servers.json entry — Desktop Settings can
// clear CurrServer while leaving a partial entry for later reuse.
func getCurrServerName() string {
	return config.CurrServer
}

func isRegisteredToServer() bool {
	server := serverAddress()
	if server == "" {
		return false
	}
	srv := config.GetServer(server)
	return srv != nil && strings.TrimSpace(srv.Server) != ""
}

func listConnections() (map[string]*Connection, error) {
	nodes := config.GetNodes()
	result := make(map[string]*Connection, len(nodes))
	for network, node := range nodes {
		conn := &Connection{
			Gateways: []any{},
		}
		if node.Connected {
			conn.Status = InterfaceStatusUp
		} else {
			conn.Status = InterfaceStatusDown
		}
		if node.Address.IP != nil {
			addr := node.Address.String()
			conn.Address = &addr
		}
		mtu := config.DefaultMTU
		conn.MTU = &mtu
		result[network] = conn
	}
	return result, nil
}

func prepareConnect(network string) ([]string, error) {
	if !racRestrictToSingleNetwork() {
		return nil, nil
	}
	var disconnect []string
	for name, node := range config.GetNodes() {
		if name == network || !node.Connected {
			continue
		}
		disconnect = append(disconnect, name)
	}
	return disconnect, nil
}

// ActiveExitNetwork is another connected network that already owns the default
// route / exit intent. The network being acted on (except) is never returned.
//
// Desire is checked first so a clear→reselect on the owner network is not
// blocked, and so a second network cannot steal exit while routes flap.
// When desire is absent but the host still has a default route, ownership is
// inferred only in the single-connected-network case. With two+ networks up,
// blaming a sibling (e.g. after clear→assign) caused false 409s and exit theft.
func ActiveExitNetwork(except string) string {
	user, tenant := SessionIdentity()
	if desiredExitIntent(user, tenant) {
		name := strings.TrimSpace(config.GetDesiredExitNetwork(user, tenant))
		if name == except {
			return ""
		}
		if name != "" && config.GetNode(name).Connected {
			return name
		}
	}
	if !HostHasDefaultRoute() {
		return ""
	}
	var connected []string
	for name, node := range config.GetNodes() {
		if !node.Connected {
			continue
		}
		connected = append(connected, name)
	}
	if len(connected) == 1 && connected[0] != except {
		return connected[0]
	}
	return ""
}

// HostHasDefaultRoute reports whether the host currently has Netmaker IGW
// (CurrGw) or a peer advertising 0.0.0.0/0 / ::/0.
func HostHasDefaultRoute() bool {
	return hostHasDefaultRoute()
}

// HostHasInstalledIGW is true only when CurrGw is set (routes installed).
// Peer AllowedIPs can still advertise 0.0.0.0/0 after a clear until MQTT
// converges — that must not block a new select or look like a foreign exit.
func HostHasInstalledIGW() bool {
	return hostHasInstalledIGW()
}

// HasOtherConnectedNetwork is true when any network other than except is up.
func HasOtherConnectedNetwork(except string) bool {
	for name, node := range config.GetNodes() {
		if name == except || !node.Connected {
			continue
		}
		return true
	}
	return false
}

// ShouldDeferAutoExitClaim is true when auto-selecting an exit on network
// would steal from another network's exit (known owner) or from an installed
// IGW while multiple networks are up and desire does not name this network.
// Callers must not clear this network's server exit when this is true — it may
// be the owner (clearing kills routing right after a successful select).
func ShouldDeferAutoExitClaim(network string) bool {
	if ActiveExitNetwork(network) != "" {
		return true
	}
	user, tenant := SessionIdentity()
	if desiredExitIntent(user, tenant) {
		name := strings.TrimSpace(config.GetDesiredExitNetwork(user, tenant))
		// Desire names us, or intent without a network yet — allow claim here.
		if name == "" || name == network {
			return false
		}
		return true
	}
	return hostHasInstalledIGW() && HasOtherConnectedNetwork(network)
}

func desiredExitIntent(user, tenant string) bool {
	if config.GetDesiredWantIGW(user, tenant) || config.GetDesiredAutoExit(user, tenant) {
		return true
	}
	return strings.TrimSpace(config.GetDesiredEgressID(user, tenant)) != ""
}

func hostHasInstalledIGW() bool {
	nc := config.Netclient()
	if nc == nil {
		return false
	}
	return len(nc.CurrGwNmIP) > 0 || len(nc.CurrGwNmIP6) > 0
}

func hostHasDefaultRoute() bool {
	nc := config.Netclient()
	if nc == nil {
		return false
	}
	if len(nc.CurrGwNmIP) > 0 || len(nc.CurrGwNmIP6) > 0 {
		return true
	}
	for _, peer := range nc.HostPeers {
		for _, cidr := range peer.AllowedIPs {
			if cidr.String() == "0.0.0.0/0" || cidr.String() == "::/0" {
				return true
			}
		}
	}
	return false
}
