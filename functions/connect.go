package functions

import (
	"errors"
	"fmt"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/dns"
	"github.com/gravitl/netclient/wireguard"
	"golang.org/x/exp/slog"
)

// Disconnect disconnects a node from the given network
func Disconnect(network string) error {
	return disconnectNetwork(network, true, true)
}

// Connect will attempt to connect a node on given network
func Connect(network string) error {
	return connectNetwork(network, true)
}

func connectNetwork(network string, restart bool) error {
	nodes := config.GetNodes()
	node, ok := nodes[network]
	if !ok {
		return errors.New("no such network")
	}
	if node.Connected {
		return errors.New("node already connected")
	}
	token := callPrepareDesktopConnect(network)
	node.Connected = true
	config.UpdateNodeMap(node.Network, node)
	if err := config.WriteNodeConfig(); err != nil {
		return fmt.Errorf("error writing node config %w", err)
	}
	callRememberDesiredConnection(network)
	if err := PublishNodeUpdate(&node); err != nil {
		return err
	}
	if !restart {
		callFinishDesktopConnect(network, token)
		return nil
	}
	if err := applyConnectionChange("connect"); err != nil {
		return err
	}
	callFinishDesktopConnect(network, token)
	return nil
}

// applyConnectionChange brings the live interface in line with the new node set
// without bouncing the daemon, falling back to a restart only if that fails.
func applyConnectionChange(op string) error {
	if err := applyConnectionChangeInProcess(); err != nil {
		slog.Warn("in-process apply failed; falling back to daemon restart", "op", op, "error", err)
		if err := daemon.Restart(); err != nil {
			if err := daemon.Start(); err != nil {
				return fmt.Errorf("daemon restart failed %w", err)
			}
		}
	}
	return nil
}

func disconnectNetwork(network string, restart, forgetDesired bool) error {
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
	if forgetDesired {
		callForgetDesiredConnection(network)
		// Keep exit-node selection (desired + server). Disconnect only drops local
		// IGW routes/DNS below; reconnect/session restore re-applies exit.
	}
	done := logElapsed("disconnect node update publish")
	// One short attempt. The default client retries for about a minute, and
	// that wait is what made logout with an exit selected feel stuck after
	// the routes were already restored.
	err := PublishNodeUpdateOnce(&node, 5*time.Second)
	done()
	if err != nil {
		return err
	}
	if !config.AnyNodeConnected() {
		_ = wireguard.SetPeers(true)
		restoreInternetGwAndDNS()
	}
	if !restart {
		// Other networks are still up, so the iface is not rebuilt below.
		// Drop this network's listener and refresh OS DNS anyway.
		if config.AnyNodeConnected() {
			dns.ReconfigureNow(config.GetServer(node.Server))
		}
		return nil
	}
	return applyConnectionChange("disconnect")
}

// ConnectWithoutRestart marks the network connected and publishes the update
// without rebuilding the daemon. Desktop session restore uses this.
func ConnectWithoutRestart(network string) error {
	return connectNetwork(network, false)
}

// DisconnectWithoutRestart marks the network disconnected without a daemon
// restart. forgetDesired clears the desktop user's desired-connection record
// when that hook is registered.
func DisconnectWithoutRestart(network string, forgetDesired bool) error {
	return disconnectNetwork(network, false, forgetDesired)
}
