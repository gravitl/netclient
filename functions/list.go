package functions

import (
	"fmt"

	"github.com/gravitl/netclient/config"
)

type Peer struct {
	PublicKey  string
	Endpoint   string
	AllowedIPs []string
}

type CIDR struct {
	CIDR string
}

// List - list network details for specified networks
// long flag passed passed to cmd line will list additional details about network including peers
func List(net string, long bool) {
	found := false
	for network := range config.Nodes {
		if network == net || net == "all" {
			found = true
			node := config.Nodes[network]
			connected := "Not Connected"
			if node.Connected {
				connected = "Connected"
			}
			fmt.Println()
			fmt.Println(node.Network, connected, node.ID, node.Address.String(), node.Address6.String())
			if long {
				peers := node.Peers
				fmt.Println("  Peers:")
				for _, peer := range peers {
					fmt.Println("    ", peer.PublicKey, peer.Endpoint, "\n    AllowedIPs:")
					for _, cidr := range peer.AllowedIPs {
						fmt.Println("    ", cidr.String())
					}
				}
			}
		}
	}
	if !found {
		fmt.Println("\nno such network")
	}
}
