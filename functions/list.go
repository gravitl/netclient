package functions

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
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
					continue
				}
				for _, peer := range peers {
					fmt.Println(peer.PublicKey, peer.Endpoint)
					for _, cidr := range peer.AllowedIPs {
						fmt.Println(cidr)
					}
				}
			}
		}
	}
}

func getPeers(node *config.Node) ([]Peer, error) {
	var response []Peer
	server := config.Servers[node.Server]
	token, err := Authenticate(node)
	if err != nil {
		return response, err
	}
	endpoint := httpclient.JSONEndpoint[models.NodeGet]{
		URL:           "https://" + server.API,
		Route:         "/api/node" + node.Network + "/" + node.ID,
		Method:        http.MethodGet,
		Authorization: "Bearer " + token,
		Response:      models.NodeGet{},
	}
	nodeData, err := endpoint.GetJSON(models.NodeGet{})
	if err != nil {
		return response, err
	}
	for i, peer := range nodeData.(models.NodeGet).Peers {
		response[i].PublicKey = peer.PublicKey.String()
		response[i].Endpoint = peer.Endpoint.String()
		for j, ip := range peer.AllowedIPs {
			response[i].AllowedIPs[j] = ip.String()
		}

	}
	return response, nil
}
