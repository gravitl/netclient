package functions

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/local"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// Uninstall - uninstalls networks from client
func Uninstall() {
	for network := range config.Nodes {
		if err := LeaveNetwork(network); err != nil {
			logger.Log(1, "encountered issue leaving network", network, ":", err.Error())
		}
	}
	// clean up OS specific stuff
	//if ncutils.IsWindows() {
	//daemon.CleanupWindows()
	//} else if ncutils.IsMac() {
	//daemon.CleanupMac()
	//} else if ncutils.IsLinux() {
	daemon.CleanupLinux()
	//} else if ncutils.IsFreeBSD() {
	//daemon.CleanupFreebsd()
	//} else if !ncutils.IsKernel() {
	//logger.Log(1, "manual cleanup required")
	//}
}

// LeaveNetwork - client exits a network
func LeaveNetwork(network string) error {
	logger.Log(0, "leaving network", network)
	node := config.Nodes[network]
	logger.Log(2, "deleting node from server")
	if err := deleteNodeFromServer(&node); err != nil {
		logger.Log(0, "error deleting node from server", err.Error())
	}
	logger.Log(2, "deleting wireguard interface")
	if err := deleteLocalNetwork(&node); err != nil {
		logger.Log(0, "error deleting wireguard interface", err.Error())
	}
	logger.Log(2, "deleting configuration files")
	if err := WipeLocal(&node); err != nil {
		logger.Log(0, "error deleting local network files", err.Error())
	}
	logger.Log(2, "removing dns entries")
	if err := removeHostDNS(node.Interface, ncutils.IsWindows()); err != nil {
		logger.Log(0, "failed to delete dns entries for", node.Interface, err.Error())
	}
	if config.Netclient.DaemonInstalled {
		logger.Log(2, "restarting daemon")
		return daemon.Restart()
	}
	return nil
}

func deleteNodeFromServer(node *config.Node) error {
	if node.IsServer {
		return errors.New("attempt to delete server node ... not permitted")
	}
	token, err := Authenticate(node)
	if err != nil {
		return fmt.Errorf("unable to authenticate %w", err)
	}
	server := config.Servers[node.Server]
	if err != nil {
		return fmt.Errorf("could not read sever config %w", err)
	}
	endpoint := httpclient.Endpoint{
		URL:    "https://" + server.API,
		Method: http.MethodDelete,
		Route:  "/api/nodes/" + node.Network + "/" + node.ID,
		Headers: []httpclient.Header{
			{
				Name:  "requestfrom",
				Value: "node",
			},
		},
		Authorization: "Bearer " + token,
	}
	response, err := endpoint.GetResponse()
	if err != nil {
		return fmt.Errorf("error deleting node on server: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		bodybytes, _ := io.ReadAll(response.Body)
		defer response.Body.Close()
		return fmt.Errorf("error deleting node from network %s on server %s %s", node.Network, response.Status, string(bodybytes))
	}
	return nil
}

func deleteLocalNetwork(node *config.Node) error {
	wgClient, wgErr := wgctrl.New()
	if wgErr != nil {
		return wgErr
	}
	defer wgClient.Close()
	removeIface := node.Interface
	queryAddr := node.PrimaryAddress()
	if ncutils.IsMac() {
		var macIface string
		macIface, wgErr = local.GetMacIface(queryAddr.IP.String())
		if wgErr == nil && removeIface != "" {
			removeIface = macIface
		}
	}
	dev, err := wgClient.Device(removeIface)
	if err != nil {
		return fmt.Errorf("error flushing routes %w", err)
	}
	local.FlushPeerRoutes(removeIface, dev.Peers[:])
	local.RemoveCIDRRoute(removeIface, &node.NetworkRange)
	return nil
}

// WipeLocal - wipes local instance
func WipeLocal(node *config.Node) error {
	fail := false
	nc := wireguard.NewNCIface(node)
	if err := nc.Close(); err == nil {
		logger.Log(1, "network:", node.Network, "removed WireGuard interface: ", node.Interface)
	} else if os.IsNotExist(err) {
		err = nil
	} else {
		fail = true
	}
	if err := os.Remove(config.GetNetclientInterfacePath() + node.Interface + ".conf"); err != nil {
		logger.Log(0, "failed to delete file", err.Error())
		fail = true
	}
	//remove node from map of nodes
	delete(config.Nodes, node.Network)
	//remove node from list of nodes that server handles
	server := config.GetServer(node.Server)
	delete(server.Nodes, node.Network)
	//if server node list is empty delete server from map of servers
	if len(server.Nodes) == 0 {
		delete(config.Servers, node.Server)
	}
	config.WriteNodeConfig()
	config.WriteServerConfig()
	if fail {
		return errors.New("not all files were deleted")
	}
	return nil
}
