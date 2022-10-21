package functions

import (
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
)

// Disconnect - disconnects a node from the given network
func Disconnect(network string) {
	node, err := config.ReadNodeConfig(network)
	if err != nil {
		logger.Log(0, "failed to read node config for network", network, "with error", err.Error())
		return
	}
	if !node.Connected {
		logger.Log(0, "node already disconnected")
		return
	}
	node.Connected = false
	if err := config.WriteNodeConfig(node); err != nil {
		logger.Log(0, "failed to write node config for", node.Name, "on network", network, "with error", err.Error())
		return
	}
	filePath := config.GetNetclientNodePath() + node.Interface + ".conf"
	wireguard.ApplyConf(node, filePath)
	//if err := setupMQTTSingleton(cfg); err != nil {
	//return err
	//}
	//if err := PublishNodeUpdate(cfg); err != nil {
	//return err
	//}
	if err := daemon.Restart(); err != nil {
		logger.Log(0, "daemon restart failed", err.Error())
	}
}

// Connect - will attempt to connect a node on given network
func Connect(network string) {
	node, err := config.ReadNodeConfig(network)
	if err != nil {
		logger.Log(0, "failed to read node config for network", network, "with error", err.Error())
		return
	}
	if node.Connected {
		logger.Log(0, "node already connected")
		return
	}
	node.Connected = true
	if err := config.WriteNodeConfig(node); err != nil {
		logger.Log(0, "failed to write node config for", node.Name, "on network", network, "with error", err.Error())
		return
	}
	filePath := config.GetNetclientNodePath() + node.Interface + ".conf"
	wireguard.ApplyConf(node, filePath)
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
