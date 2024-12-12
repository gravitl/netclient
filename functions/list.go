package functions

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

type output struct {
	Network   string    `json:"network"`
	NodeID    string    `json:"node_id"`
	Connected bool      `json:"connected"`
	Ipv4Addr  string    `json:"ipv4_addr"`
	Ipv6Addr  string    `json:"ipv6_addr"`
	Peers     []peerOut `json:"peers,omitempty"`
}

type peerOut struct {
	PublicKey  string   `json:"public_key"`
	Endpoint   string   `json:"endpoint"`
	AllowedIps []string `json:"allowed_ips"`
}

// List - list network details for specified networks
// long flag passed passed to cmd line will list additional details about network including peers
func List(net string, long bool) {
	listOutput := []output{}
	found := false
	nodes := config.GetNodes()
	for _, node := range nodes {
		if node.Network != net && net != "" {
			continue
		}
		nodeGet, err := GetNodePeers(node)
		if err != nil {
			logger.Log(1, "failed to get peers for node: ", node.ID.String(), " Err: ", err.Error())
			continue
		}
		found = true
		output := output{
			Network:   nodeGet.Node.NetworkName,
			Connected: node.Connected,
			NodeID:    node.ID.String(),
			Peers:     []peerOut{},
		}
		if node.Address.IP != nil {
			output.Ipv4Addr = node.Address.String()
		}
		if node.Address6.IP != nil {
			output.Ipv6Addr = node.Address6.String()
		}
		if long {
			for _, peer := range nodeGet.Peers {
				p := peerOut{
					PublicKey: peer.PublicKey.String(),
				}
				if peer.Endpoint != nil {
					p.Endpoint = peer.Endpoint.String()
				}

				for _, cidr := range peer.AllowedIPs {
					p.AllowedIps = append(p.AllowedIps, cidr.String())
				}
				output.Peers = append(output.Peers, p)
			}
		}
		listOutput = append(listOutput, output)
	}
	if !found {
		fmt.Println("\nno such network")
	} else {
		out, err := json.MarshalIndent(listOutput, "", " ")
		if err != nil {
			logger.Log(0, "failed to marshal list output: ", err.Error())
		}
		fmt.Println(string(out))
	}
}

// GetNodePeers returns the peers for a given node
func GetNodePeers(node config.Node) (models.NodeGet, error) {

	server := config.GetServer(node.Server)
	if server == nil {
		return models.NodeGet{}, errors.New("server config not found")
	}
	host := config.Netclient()
	if host == nil {
		return models.NodeGet{}, fmt.Errorf("no configured host found")
	}
	token, err := auth.Authenticate(server, host)
	if err != nil {
		return models.NodeGet{}, err
	}
	endpoint := httpclient.JSONEndpoint[models.NodeGet, models.ErrorResponse]{
		URL:           "https://" + server.API,
		Route:         "/api/nodes/" + node.Network + "/" + node.ID.String(),
		Method:        http.MethodGet,
		Authorization: "Bearer " + token,
		Response:      models.NodeGet{},
		ErrorResponse: models.ErrorResponse{},
	}
	nodeGet, errData, err := endpoint.GetJSON(models.NodeGet{}, models.ErrorResponse{})
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			logger.Log(0, "error getting node", strconv.Itoa(errData.Code), errData.Message)
		}
		return models.NodeGet{}, err
	}
	return nodeGet, nil
}
