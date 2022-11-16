package functions

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/kr/pretty"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Peer struct {
	PublicKey  string
	Endpoint   string
	AllowedIPs []string
}

type CIDR struct {
	CIDR string
}

// List - list network details for specified networks
// long flag passed passed to cmd line will list additional details about network including peers
func List(net string, long bool) {
	found := false
	for network := range config.Nodes {
		if network == net || net == "all" {
			found = true
			node := config.Nodes[network]
			connected := "Not Connected"
			if node.Connected {
				connected = "Connected"
			}
			fmt.Println()
			fmt.Println(node.Network, connected, node.ID, node.Address.String(), node.Address6.String())
			if long {
				peers, err := getPeers(&node)
				if err != nil {
					logger.Log(0, "error retrieving peers", err.Error())
					pretty.Println(peers)
					continue
				}
				fmt.Println("  Peers:")
				for _, peer := range peers {
					fmt.Println("    ", peer.PublicKey, peer.Endpoint, "\n    AllowedIPs:")
					for _, cidr := range peer.AllowedIPs {
						fmt.Println("    ", cidr.String())
					}
				}
			}
		}
	}
	if !found {
		fmt.Println("\nno such network")
	}
}

func getPeers(node *config.Node) ([]wgtypes.PeerConfig, error) {
	server := config.GetServer(node.Server)
	token, err := Authenticate(node, &config.Netclient)
	if err != nil {
		return nil, err
	}
	endpoint := httpclient.Endpoint{
		URL:           "https://" + server.API,
		Route:         "/api/nodes/" + node.Network + "/" + node.ID,
		Method:        http.MethodGet,
		Authorization: "Bearer " + token,
		//Response:      models.NodeGet{},
	}
	response, err := endpoint.GetResponse()
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		bytes, err := io.ReadAll(response.Body)
		if err == nil {
			logger.Log(3, "response from getPeers", string(bytes))
		}
		return nil, errors.New(response.Status)
	}
	nodeData := models.NodeGet{}
	if err := json.NewDecoder(response.Body).Decode(&nodeData); err != nil {
		return nil, err
	}
	return nodeData.Peers, nil
}
