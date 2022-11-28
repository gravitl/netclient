package functions

import (
	"errors"
	"fmt"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
)

// Disconnect - disconnects a node from the given network
func Disconnect(network string) error {
	node := config.Nodes[network]
	if !node.Connected {
		return errors.New("node is already disconnected")
	}
	node.Connected = false
	config.Nodes[node.Network] = node
	if err := config.WriteNodeConfig(); err != nil {
		return fmt.Errorf("failed to write node config %w, err")
	}
	if err := daemon.Restart(); err != nil {
		return fmt.Errorf("daemon restart failed %w", err)
	}
	return nil
}

// Connect - will attempt to connect a node on given network
func Connect(network string) error {
	node := config.Nodes[network]
	if node.Connected {
		return errors.New("node already connected")
	}
	node.Connected = true
	config.Nodes[node.Network] = node
	if err := config.WriteNodeConfig(); err != nil {
		return fmt.Errorf("failed to write node config %w", err)
	}
	if err := daemon.Restart(); err != nil {
		return fmt.Errorf("daemon restart failed %w", err)
	}
	return nil
}
