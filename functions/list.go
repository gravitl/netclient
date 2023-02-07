package functions

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/kr/pretty"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// List - list network details for specified networks
// long flag passed passed to cmd line will list additional details about network including peers
func List(net string, long bool) {
	output := make([]map[string]any, 0)
	found := false
	nodes := config.GetNodes()
	for network := range nodes {
		if network == net || net == "" {
			found = true
			node := nodes[network]
			entry := map[string]any{
				"network":      node.Network,
				"connected":    node.Connected,
				"id":           node.ID,
				"ipv4_address": node.Address.String(),
				"ipv6_address": node.Address6.String(),
			}
			if long {
				peers, err := GetNodePeers(node)
				if err != nil {
					logger.Log(1, "failed to get peers for node: ", node.ID.String(), " Err: ", err.Error())
					continue
				}
				if len(peers) == 0 {
					logger.Log(1, "no peers present on network", node.Network)
					continue
				}
				entry["peers"] = make([]map[string]any, 0)
				for _, peer := range peers {
					p := map[string]any{
						"public_key":  peer.PublicKey,
						"endpoint":    peer.Endpoint,
						"allowed_ips": make([]string, 0),
					}
					for _, cidr := range peer.AllowedIPs {
						p["allowed_ips"] = append(p["allowed_ips"].([]string), cidr.String())
					}
					entry["peers"] = append(entry["peers"].([]map[string]any), p)
				}
			}
			output = append(output, entry)
		}
	}
	if !found {
		fmt.Println("\nno such network")
	} else {
		pretty.Print(output)
	}
}

// GetNodePeers returns the peers for a given node
func GetNodePeers(node config.Node) ([]wgtypes.PeerConfig, error) {

	server := config.GetServer(node.Server)
	host := config.Netclient()
	if host == nil {
		return nil, fmt.Errorf("no configured host found")
	}
	token, err := Authenticate(server.API, host)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	return nodeGet.Peers, nil
}
