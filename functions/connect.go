package functions

import (
	"errors"
	"fmt"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Disconnect - disconnects a node from the given network
func Disconnect(network string) {
	node, ok := config.Nodes[network]
	if !ok {
		logger.Log(0, "no such network")
		return
	}
	if !node.Connected {
		return errors.New("node is already disconnected")
	}
	node.Connected = false
	config.Nodes[node.Network] = node
	if err := config.WriteNodeConfig(); err != nil {
		return fmt.Errorf("failed to write node config %w", err)
	}
	peers := []wgtypes.PeerConfig{}
	for _, node := range config.Nodes {
		if node.Connected {
			peers = append(peers, node.Peers...)
		}
	}
	wireguard.UpdateWgPeers(peers)
	if err := daemon.Restart(); err != nil {
		return fmt.Errorf("daemon restart failed %w", err)
	}
	return nil
}

// Connect - will attempt to connect a node on given network
func Connect(network string) {
	node, ok := config.Nodes[network]
	if !ok {
		logger.Log(0, "no such network")
		return
	}
	if node.Connected {
		return errors.New("node already connected")
	}
	node.Connected = true
	config.Nodes[node.Network] = node
	if err := config.WriteNodeConfig(); err != nil {
		return fmt.Errorf("failed to write node config %w", err)
	}
	peers := []wgtypes.PeerConfig{}
	for _, node := range config.Nodes {
		if node.Connected {
			peers = append(peers, node.Peers...)
		}
	}
	wireguard.UpdateWgPeers(peers)
	if err := daemon.Restart(); err != nil {
		return fmt.Errorf("daemon restart failed %w", err)
	}
	return nil
}
