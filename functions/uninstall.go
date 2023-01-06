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
	"github.com/gravitl/netmaker/logger"
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
	if err := daemon.CleanUp(); err != nil {
		allfaults = append(allfaults, err)
	}
	return allfaults, err
}

// LeaveNetwork - client exits a network
func LeaveNetwork(network string) ([]error, error) {
	faults := []error{}
	fmt.Println("\nleaving network", network)
	node, ok := config.Nodes[network]
	if !ok {
		fmt.Printf("\nnot connected to network: %s", network)
		return faults, fmt.Errorf("not connected to network: %s", network)
	}
	fmt.Println("deleting node from server")
	if err := deleteNodeFromServer(&node); err != nil {
		faults = append(faults, fmt.Errorf("error deleting nodes from server %w", err))
	}
	fmt.Println("deleting wireguard interface")
	if err := deleteLocalNetwork(&node); err != nil {
		faults = append(faults, fmt.Errorf("error deleting wireguard interface %w", err))
	}
	fmt.Println("removing dns entries")
	if err := removeHostDNS(node.Network); err != nil {
		faults = append(faults, fmt.Errorf("failed to delete dns entries %w", err))
	}
	if config.Netclient().DaemonInstalled {
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
		Route:  "/api/nodes/" + node.Network + "/" + node.ID.String(),
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
		logger.Log(0, "removing wireguard config")
		os.RemoveAll(config.GetNetclientPath() + "netmaker.conf")
	}
	return nil
}
