package functions

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/routes"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// Uninstall - uninstalls networks from client
func Uninstall() ([]error, error) {
	allfaults := []error{}
	var err error

	for _, v := range config.Servers {
		v := v
		if err = setupMQTTSingleton(&v, true); err != nil {
			logger.Log(0, "failed to connect to server on uninstall", v.Name)
			allfaults = append(allfaults, err)
			continue
		}
		if err = PublishHostUpdate(v.Name, models.DeleteHost); err != nil {
			logger.Log(0, "failed to notify server", v.Name, "of host removal")
			allfaults = append(allfaults, err)
		}
		Mqclient.Disconnect(250)
	}
	if err := deleteAllDNS(); err != nil {
		logger.Log(0, "failed to delete entries from /etc/hosts", err.Error())
	}

	if err = daemon.CleanUp(); err != nil {
		allfaults = append(allfaults, err)
	}

	if runtime.GOOS == "windows" {
		err = errors.New("please complete the uninstall using the add/remove program. https://docs.netmaker.io/netclient.html#uninstalling%22")
		allfaults = append(allfaults, errors.New("please complete the uninstall using the add/remove program. https://docs.netmaker.io/netclient.html#uninstalling%22"))
	}
	return allfaults, err
}

// LeaveNetwork - client exits a network
func LeaveNetwork(network string, isDaemon bool) ([]error, error) {
	faults := []error{}
	node, ok := config.Nodes[network]
	if !ok {
		return faults, fmt.Errorf("not connected to network: %s", network)
	}
	if err := deleteNodeFromServer(&node); err != nil {
		faults = append(faults, fmt.Errorf("error deleting nodes from server %w", err))
	}
	// remove node from config
	if err := deleteLocalNetwork(&node); err != nil {
		faults = append(faults, fmt.Errorf("error deleting wireguard interface %w", err))
	}
	if err := deleteNetworkDNS(network); err != nil {
		faults = append(faults, fmt.Errorf("error deleting dns entries %w", err))
	}
	// re-configure interface if daemon is calling leave
	if isDaemon {
		nc := wireguard.GetInterface()
		nc.Close()
		nc = wireguard.NewNCIface(config.Netclient(), config.GetNodes())
		nc.Create()
		if err := nc.Configure(); err != nil {
			faults = append(faults, fmt.Errorf("failed to configure interface during node removal - %v", err.Error()))
		} else {
			if err = wireguard.SetPeers(true); err != nil {
				faults = append(faults, fmt.Errorf("issue setting peers after node removal - %v", err.Error()))
			}
			if err = routes.SetNetmakerPeerEndpointRoutes(config.Netclient().DefaultInterface); err != nil {
				faults = append(faults, fmt.Errorf("issue setting peers routes after node removal - %v", err.Error()))
			}
		}
	} else { // was called from CLI so restart daemon
		if err := daemon.Restart(); err != nil {
			faults = append(faults, fmt.Errorf("could not restart daemon after leave - %v", err.Error()))
		}
	}

	if len(faults) > 0 {
		return faults, errors.New("error(s) leaving nework")
	}
	return faults, nil
}

func deleteNodeFromServer(node *config.Node) error {
	server := config.GetServer(node.Server)
	if server == nil {
		return errors.New("server config not found")
	}
	token, err := auth.Authenticate(server, config.Netclient())
	if err != nil {
		return fmt.Errorf("unable to authenticate %w", err)
	}
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
	if server != nil {
		//remove node from server node map
		delete(server.Nodes, node.Network)
		if len(server.Nodes) == 0 {
			logger.Log(3, "removing server peers", server.Name)
			config.DeleteServerHostPeerCfg()
		}
	}

	config.WriteNetclientConfig()
	config.WriteNodeConfig()
	config.WriteServerConfig()
	return nil
}
