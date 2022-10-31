package functions

import (
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
)

// Disconnect - disconnects a node from the given network
func Disconnect(network string) {
	node := config.Nodes[network]
	if !node.Connected {
		logger.Log(0, "node already disconnected")
		return
	}
	node.Connected = false
	config.Nodes[node.Network] = node
	if err := config.WriteNodeConfig(node); err != nil {
		logger.Log(0, "failed to write node config for", node.Name, "on network", network, "with error", err.Error())
		return
	}
	filePath := config.GetNetclientInterfacePath() + node.Interface + ".yml"
	wireguard.ApplyConf(&node, filePath)
	if err := daemon.Restart(); err != nil {
		logger.Log(0, "daemon restart failed", err.Error())
	}
}

// Connect - will attempt to connect a node on given network
func Connect(network string) {
	node := config.Nodes[network]
	if node.Connected {
		logger.Log(0, "node already connected")
		return
	}
	node.Connected = true
	config.Nodes[node.Network] = node
	if err := config.WriteNodeConfig(node); err != nil {
		logger.Log(0, "failed to write node config for", node.Name, "on network", network, "with error", err.Error())
		return
	}
	filePath := config.GetNetclientInterfacePath() + node.Interface + ".yml"
	wireguard.ApplyConf(&node, filePath)
	//if err := setupMQTTSingleton(cfg); err != nil {
	//	return err
	//}
	//if err := PublishNodeUpdate(cfg); err != nil {
	//	return err
	//}
	if err := daemon.Restart(); err != nil {
		logger.Log(0, "daemon restart failed", err.Error())
	}
}
