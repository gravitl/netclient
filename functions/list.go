package functions

import (
	"fmt"

	"github.com/gravitl/netclient/config"
)

// List - list network details for specified networks
// long flag passed passed to cmd line will list additional details about network including peers
func List(net string, long bool) {
	found := false
	nodes := config.GetNodes()
	for network := range nodes {
		if network == net || net == "" {
			found = true
			node := nodes[network]
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
