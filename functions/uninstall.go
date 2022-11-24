package functions

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/local"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/vishvananda/netlink"
)

// Uninstall - uninstalls networks from client
func Uninstall() ([]error, error) {
	allfaults := []error{}
	var err error
	for network := range config.Nodes {
		faults, err := LeaveNetwork(network)
		if err != nil {
			allfaults = append(allfaults, faults...)
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
	return allfaults, err
}

// LeaveNetwork - client exits a network
func LeaveNetwork(network string) ([]error, error) {
	faults := []error{}
	fmt.Println("\nleaving network", network)
	node := config.Nodes[network]
	fmt.Println("deleting node from server")
	if err := deleteNodeFromServer(&node); err != nil {
		faults = append(faults, fmt.Errorf("error deleting nodes from server %w", err))
	}
	fmt.Println("deleting wireguard interface")
	if err := deleteLocalNetwork(&node); err != nil {
		faults = append(faults, fmt.Errorf("error deleting wireguard interface %w", err))
	}
	logger.Log(2, "removing dns entries")
	if err := removeHostDNS(network); err != nil {
		logger.Log(0, "failed to delete dns entries", err.Error())
	}
	fmt.Println("removing dns entries")
	if err := removeHostDNS(node.Interface, ncutils.IsWindows()); err != nil {
		faults = append(faults, fmt.Errorf("failed to delete dns entries %w", err))
	}
	if config.Netclient.DaemonInstalled {
		fmt.Println("restarting daemon")
		if err := daemon.Restart(); err != nil {
			faults = append(faults, fmt.Errorf("error restarting daemon %w", err))
		}
	}
	if len(faults) > 0 {
		return faults, errors.New("error(s) leaving nework")
	}
	return faults, nil
}

func deleteNodeFromServer(node *config.Node) error {
	if node.IsServer {
		return errors.New("attempt to delete server node ... not permitted")
	}
	token, err := Authenticate(node, config.Netclient())
	if err != nil {
		return fmt.Errorf("unable to authenticate %w", err)
	}
	server := config.GetServer(node.Server)
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
	nodetodelete := config.GetNode(node.Network)
	if nodetodelete.Network == "" {
		return errors.New("no such network")
	}
	local.FlushPeerRoutes(node.Peers[:])
	if node.NetworkRange.IP != nil {
		local.RemoveCIDRRoute(&node.NetworkRange)
	}
	if node.NetworkRange6.IP != nil {
		local.RemoveCIDRRoute(&node.NetworkRange6)
	}
	//remove node from nodes map
	config.DeleteNode(node.Network)
	server := config.GetServer(node.Server)
	//remove node from server node map
	if server != nil {
		nodes := server.Nodes
		delete(nodes, node.Network)
	}
	if len(server.Nodes) == 0 {
		logger.Log(3, "removing server", server.Name)
		config.DeleteServer(node.Server)
	}
	config.WriteNodeConfig()
	config.WriteServerConfig()
	if len(config.GetNodes()) < 1 {
		logger.Log(0, "removing wireguard config and netmaker interface")
		os.RemoveAll(config.GetNetclientPath() + "netmaker.conf")
		link, err := netlink.LinkByName("netmaker")
		if err != nil {
			return err
		}
		if err := netlink.LinkDel(link); err != nil {
			return err
		}
	} else {
		log.Println(len(config.GetNodes()), "nodes left, leave netmaker interface up")
	}
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
	if err := os.Remove(config.GetNetclientInterfacePath() + config.Netclient.Interface + ".conf"); err != nil {
		logger.Log(0, "failed to delete file", err.Error())
		fail = true
	}
	//remove node from map of nodes
	delete(config.Nodes, node.Network)
	//remove node from list of nodes that server handles
	server := config.GetServer(node.Server)
	//remove node from server node map
	if server != nil {
		nodes := server.Nodes
		delete(nodes, node.Network)
	}
	if len(server.Nodes) == 0 {
		logger.Log(3, "removing server", server.Name)
		config.DeleteServer(node.Server)
	}
	config.WriteNodeConfig()
	config.WriteServerConfig()
	if len(config.GetNodes()) < 1 {
		logger.Log(0, "removing wireguard config and netmaker interface")
		os.RemoveAll(config.GetNetclientPath() + "netmaker.conf")
		link, err := netlink.LinkByName("netmaker")
		if err != nil {
			return err
		}
		if err := netlink.LinkDel(link); err != nil {
			return err
		}
	}
	return nil
}
