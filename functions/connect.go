package functions

import (
	"errors"
	"fmt"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
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
	server := config.GetServer(node.Server)
	if server == nil {
		return errors.New("server cfg is nil")
	}
	if err := setupMQTTSingleton(server, true); err != nil {
		return err
	}
	if err := PublishNodeUpdate(&node); err != nil {
		return err
	}
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
	server := config.GetServer(node.Server)
	if server == nil {
		return errors.New("server cfg is nil")
	}
	if err := setupMQTTSingleton(server, true); err != nil {
		return err
	}
	if err := PublishNodeUpdate(&node); err != nil {
		return err
	}
	if err := daemon.Restart(); err != nil {
		if err := daemon.Start(); err != nil {
			return fmt.Errorf("daemon restart failed %w", err)
		}
	}
	return nil
}
