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
				peers, err := getNodePeers(node)
				if err != nil {
					logger.Log(1, "failed to get peers for node: ", node.ID.String(), " Err: ", err.Error())
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

func getNodePeers(node config.Node) ([]wgtypes.PeerConfig, error) {

	server := config.GetServer(node.Server)
	token, err := Authenticate(&node, config.Netclient())
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
