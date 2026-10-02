package uiapi

import (
	"strings"

	"github.com/gravitl/netclient/config"
)

func getCurrServerName() string {
	if config.CurrServer != "" {
		return config.CurrServer
	}
	if key := config.ResolveServerKey(""); key != "" {
		return key
	}
	return ""
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
// route. The network being connected is not treated as that gateway.
func ActiveExitNetwork(except string) string {
	if !hostHasDefaultRoute() {
		return ""
	}
	user, tenant := SessionIdentity()
	if config.GetDesiredWantIGW(user, tenant) {
		name := strings.TrimSpace(config.GetDesiredExitNetwork(user, tenant))
		if name == except {
			return ""
		}
		if name != "" && config.GetNode(name).Connected {
			return name
		}
	}
	for name, node := range config.GetNodes() {
		if name == except || !node.Connected {
			continue
		}
		return name
	}
	return ""
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
