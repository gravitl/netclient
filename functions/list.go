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
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// List - list network details for specified networks
// long flag passed passed to cmd line will list additional details about network including peers
func List(net string, long bool) {
	found := false
	nodes := config.GetNodes()
	for network := range nodes {
		if network == net || net == "" {
			found = true
			node := nodes[network]
			connected := "Not Connected"
			if node.Connected {
				connected = "Connected"
			}
			fmt.Println()
			fmt.Println(node.Network, connected, node.ID, node.Address.String(), node.Address6.String())
			if long {
				peers := node.Peers
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
