package functions

import (
	"fmt"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netmaker/logger"
)

// Disconnect - disconnects a node from the given network
func Disconnect(network string) {
	node := config.Nodes[network]
	if !node.Connected {
		fmt.Println("\nnode already disconnected from", network)
		return
	}
	node.Connected = false
	config.Nodes[node.Network] = node
	if err := config.WriteNodeConfig(); err != nil {
		logger.Log(0, "failed to write node config for", node.Name, "on network", network, "with error", err.Error())
		return
	}

	if err := daemon.Restart(); err != nil {
		logger.Log(0, "daemon restart failed", err.Error())
	}
	fmt.Println("\nnode is disconnected from", network)
}

// Connect - will attempt to connect a node on given network
func Connect(network string) {
	node := config.Nodes[network]
	if node.Connected {
		fmt.Println("\nnode already connected to", network)
		return
	}
	node.Connected = true
	config.Nodes[node.Network] = node
	if err := config.WriteNodeConfig(); err != nil {
		logger.Log(0, "failed to write node config for", node.Name, "on network", network, "with error", err.Error())
		return
	}
	// filePath := config.GetNetclientInterfacePath() + node.Interface + ".conf"
	//if err := setupMQTTSingleton(cfg); err != nil {
	//	return err
	//}
	//if err := PublishNodeUpdate(cfg); err != nil {
	//	return err
	//}

	if err := daemon.Restart(); err != nil {
		logger.Log(0, "daemon restart failed", err.Error())
	}
	fmt.Println("\nnode is connected to", network)
}
