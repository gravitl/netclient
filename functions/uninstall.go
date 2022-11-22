package functions

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/local"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
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
	node, ok := config.Nodes[network]
	if !ok {
		return errors.New("no such network")
	}
	logger.Log(2, "deleting node from server")
	if err := deleteNodeFromServer(&node); err != nil {
		logger.Log(0, "error deleting node from server", err.Error())
	}
	logger.Log(2, "deleting node from client")
	if err := deleteLocalNetwork(&node); err != nil {
		logger.Log(0, "error deleting local node", err.Error())
		return err
	}
	logger.Log(2, "removing dns entries")
	if err := removeHostDNS(config.Netclient.Interface, ncutils.IsWindows()); err != nil {
		logger.Log(0, "failed to delete dns entries", err.Error())
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
	token, err := Authenticate(node, &config.Netclient)
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
	if _, ok := config.Nodes[node.Network]; !ok {
		return errors.New("no such network")
	}
	delete(config.Nodes, node.Network)
	server := config.GetServer(node.Server)
	if server != nil {
		nodes := server.Nodes
		delete(nodes, node.Network)
	}
	if len(server.Nodes) == 0 {
		logger.Log(3, "removing server", server.Name)
		delete(config.Servers, node.Server)
	}
	config.WriteNodeConfig()
	config.WriteServerConfig()
	local.FlushPeerRoutes(node.Peers[:])
	if node.NetworkRange.IP != nil {
		local.RemoveCIDRRoute(&node.NetworkRange)
	}
	if node.NetworkRange6.IP != nil {
		local.RemoveCIDRRoute(&node.NetworkRange6)
	}
	return nil
}
