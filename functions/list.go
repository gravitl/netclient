package functions

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

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
	logger.Log(0, "List called with", net, strconv.FormatBool(long))
	for network := range config.Nodes {
		if network == net || net == "all" {
			node := config.Nodes[network]
			fmt.Println(node.Network, node.ID, node.Name, node.Interface, node.Address.String(), node.Address6.String())
			if long {
				peers, err := getPeers(&node)
				if err != nil {
					logger.Log(0, "error retrieving peers", err.Error())
					pretty.Println(peers)
					continue
				}
				for _, peer := range peers {
					fmt.Println("  Peers: ", peer.PublicKey, peer.Endpoint, "\n    AllowedIPs:")
					for _, cidr := range peer.AllowedIPs {
						fmt.Println("    ", cidr.String())
					}
					fmt.Println("")
				}
			}
		}
	}
}

func getPeers(node *config.Node) ([]wgtypes.PeerConfig, error) {
	server := config.GetServer(node.Server)
	token, err := Authenticate(node)
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
