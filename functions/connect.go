package functions

import (
	"fmt"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Disconnect - disconnects a node from the given network
func Disconnect(network string) {
	nodes := config.GetNodes()
	node, ok := nodes[network]
	if !ok {
		logger.Log(0, "no such network")
		return
	}
	if !node.Connected {
		fmt.Println("\nnode already disconnected from", network)
		return
	}
	node.Connected = false
	config.UpdateNodeMap(node.Network, node)
	if err := config.WriteNodeConfig(); err != nil {
		logger.Log(0, "failed to write node config for", node.ID, "on network", network, "with error", err.Error())
		return
	}
	peers := []wgtypes.PeerConfig{}
	for _, node := range nodes {
		if node.Connected {
			peers = append(peers, node.Peers...)
		}
	}
	wireguard.UpdateWgPeers(peers)
	if err := daemon.Restart(); err != nil {
		logger.Log(0, "daemon restart failed", err.Error())
	}
	fmt.Println("\nnode is disconnected from", network)
}

// Connect - will attempt to connect a node on given network
func Connect(network string) {
	nodes := config.GetNodes()
	node, ok := nodes[network]
	if !ok {
		logger.Log(0, "no such network")
		return
	}
	if node.Connected {
		fmt.Println("\nnode already connected to", network)
		return
	}
	node.Connected = true
	config.UpdateNodeMap(node.Network, node)
	if err := config.WriteNodeConfig(); err != nil {
		logger.Log(0, "failed to write node config for", node.ID, "on network", network, "with error", err.Error())
		return
	}
	peers := []wgtypes.PeerConfig{}
	for _, node := range nodes {
		if node.Connected {
			peers = append(peers, node.Peers...)
		}
	}
	wireguard.UpdateWgPeers(peers)
	if err := daemon.Restart(); err != nil {
		logger.Log(0, "daemon restart failed", err.Error())
	}
	fmt.Println("\nnode is connected to", network)
}
