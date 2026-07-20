package uiapi

import (
	"fmt"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
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

func connectedNetworkCount(except string) int {
	count := 0
	for network, node := range config.GetNodes() {
		if network == except {
			continue
		}
		if node.Connected {
			count++
		}
	}
	return count
}

func nodeHasInternetGateway(network string) bool {
	node := config.GetNode(network)
	if !node.Connected {
		return false
	}
	for _, peer := range config.Netclient().HostPeers {
		for _, cidr := range peer.AllowedIPs {
			if cidr.String() == "0.0.0.0/0" || cidr.String() == "::/0" {
				return true
			}
		}
	}
	_ = node
	return config.Netclient().CurrGwNmIP != nil
}

func connectedInternetGatewayNetwork(except string) string {
	for network := range config.GetNodes() {
		if network == except {
			continue
		}
		if nodeHasInternetGateway(network) {
			return network
		}
	}
	return ""
}

func validateConnect(network string) error {
	if igwNet := connectedInternetGatewayNetwork(network); igwNet != "" {
		if wouldConnectAsIGW(network) {
			return fmt.Errorf("can have only one active connection to internet gateway")
		}
	}
	return nil
}

func prepareConnect(network string) ([]string, error) {
	if err := validateConnect(network); err != nil {
		return nil, err
	}
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

func wouldConnectAsIGW(network string) bool {
	server := config.GetServer(config.CurrServer)
	if server == nil {
		return false
	}
	// conservative check: if host already has default gw set, another IGW connect is blocked
	if config.Netclient().CurrGwNmIP != nil {
		for _, node := range config.GetNodes() {
			if node.Network != network && node.Connected {
				return true
			}
		}
	}
	return false
}

func interfaceName() string {
	name := ncutils.GetInterfaceName()
	if name == "" {
		name = "netmaker"
	}
	return strings.TrimSpace(name)
}
