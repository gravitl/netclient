package functions

import (
	"errors"
	"fmt"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Disconnect disconnects a node from the given network
func Disconnect(network string) error {
	nodes := config.GetNodes()
	node, ok := nodes[network]
	if !ok {
		return errors.New("no such network")
	}
	if !node.Connected {
		return errors.New("node is already disconnected")
	}
	node.Connected = false
	config.UpdateNodeMap(node.Network, node)
	if err := config.WriteNodeConfig(); err != nil {
		return fmt.Errorf("error writing node config %w", err)
	}
	peers := []wgtypes.PeerConfig{}
	for _, node := range nodes {
		if node.Connected {
			peers = append(peers, node.Peers...)
		}
	}
	wireguard.UpdateWgPeers(peers)
	if err := daemon.Restart(); err != nil {
		fmt.Println("daemon restart failed", err)
		if err := daemon.Start(); err != nil {
			fmt.Println("daemon failed to start", err)
		}
	}
	return nil
}

// Connect will attempt to connect a node on given network
func Connect(network string) error {
	nodes := config.GetNodes()
	node, ok := nodes[network]
	if !ok {
		return errors.New("no such network")
	}
	if node.Connected {
		return errors.New("node already connected")
	}
	node.Connected = true
	config.UpdateNodeMap(node.Network, node)
	if err := config.WriteNodeConfig(); err != nil {
		return fmt.Errorf("error writing node config %w", err)
	}
	peers := []wgtypes.PeerConfig{DaemonInstalled}
	for _, node := range nodes {
		if node.Connected {
			peers = append(peers, node.Peers...)
		}
	}
	wireguard.UpdateWgPeers(peers)
	if err := daemon.Restart(); err != nil {
		if err := daemon.Start(); err != nil {
			return fmt.Errorf("daemon restart failed %w", err)
		}
	}
	return nil
}
