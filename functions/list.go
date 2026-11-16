package functions

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/scope"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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

// List displays this host's networks from the server (GET /api/v1/host).
// Unlike the old local-only path, disconnected nodes still appear so connect
// can target them. A successful list also refreshes nodes.json (without
// reasserting desktop desired connections).
//
// long fetches per-network peers via GET /api/nodes/{network}/{nodeID}.
func List(net string, long bool) {
	pull, err := fetchHostPull(false, false)
	if err != nil {
		fmt.Println("\nlist failed:", err)
		return
	}
	syncNodesFromServerList(pull.Nodes)

	listOutput := []output{}
	found := false
	for _, node := range pull.Nodes {
		if net != "" && node.Network != net {
			continue
		}
		found = true
		row := output{
			Network:   node.Network,
			Connected: node.Connected,
			NodeID:    node.ID.String(),
			Peers:     []peerOut{},
		}
		if node.Address.IP != nil {
			row.Ipv4Addr = node.Address.String()
		}
		if node.Address6.IP != nil {
			row.Ipv6Addr = node.Address6.String()
		}
		if long {
			cfgNode := listNodeConfig(node)
			peers, err := GetNodePeers(cfgNode)
			if err != nil {
				logger.Log(1, "failed to get peers for node: ", node.ID.String(), " Err: ", err.Error())
			}
			for _, peer := range peers {
				p := peerOut{
					PublicKey: peer.PublicKey.String(),
				}
				if peer.Endpoint != nil {
					p.Endpoint = peer.Endpoint.String()
				}
				for _, cidr := range peer.AllowedIPs {
					p.AllowedIps = append(p.AllowedIps, cidr.String())
				}
				row.Peers = append(row.Peers, p)
			}
		}
		listOutput = append(listOutput, row)
	}
	if !found {
		if net != "" {
			fmt.Println("\nno such network")
		} else {
			fmt.Println("\nno networks")
		}
		return
	}
	out, err := json.MarshalIndent(listOutput, "", " ")
	if err != nil {
		logger.Log(0, "failed to marshal list output: ", err.Error())
		return
	}
	fmt.Println(string(out))
}

// syncNodesFromServerList replaces the local node map with the host-pull set
// (includes disconnected). Preserves local Connected flags across the replace
// but does not call ReassertDesired — listing must not force reconnects.
//
// Mirrors the MQTT empty-Nodes guard: never wipe a non-empty nodes.json from a
// transient empty host-pull. Server remains source of truth for non-empty lists.
func syncNodesFromServerList(nodes []models.Node) {
	if len(nodes) == 0 && len(config.GetNodes()) > 0 {
		logger.Log(0, "list: skipping node sync; server returned empty Nodes while local nodes exist")
		return
	}
	keepDisconnected := locallyDisconnectedNetworks()
	keepConnected := locallyConnectedNetworks()
	config.SetNodes(nodes)
	keepLocallyDisconnected(keepDisconnected)
	if GUI.FilterPreserved != nil {
		keepConnected = GUI.FilterPreserved(keepConnected)
	}
	keepLocallyConnected(keepConnected)
	if err := config.WriteNodeConfig(); err != nil {
		logger.Log(0, "list: failed to write node config:", err.Error())
	}
}

func listNodeConfig(node models.Node) config.Node {
	cfg := config.Node{CommonNode: node.CommonNode}
	if strings.TrimSpace(cfg.Server) == "" {
		cfg.Server = config.CurrServer
	}
	return cfg
}

// GetNodePeers returns the peers for a given node
func GetNodePeers(node config.Node) ([]wgtypes.PeerConfig, error) {
	serverName := node.Server
	if strings.TrimSpace(serverName) == "" {
		serverName = config.CurrServer
	}
	server := config.GetServer(serverName)
	if server == nil {
		return []wgtypes.PeerConfig{}, errors.New("server config not found")
	}
	host := config.Netclient()
	if host == nil {
		return nil, fmt.Errorf("no configured host found")
	}
	token, err := auth.Authenticate(server, host)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/api/nodes/%s/%s",
		config.APIBaseURL(config.NormalizeServerAPI(server.API)), node.Network, node.ID.String())
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	auth.ApplyAPIHeaders(headers, token, host)
	headers.Set(scope.HeaderTenantID, host.TenantID)
	respBytes, err := ncutils.SendRequest(http.MethodGet, url, headers, nil)
	if err != nil {
		return nil, err
	}

	var nodeGet models.NodeGet
	err = json.Unmarshal(respBytes.Bytes(), &nodeGet)
	if err != nil {
		return nil, err
	}

	return nodeGet.Peers, nil
}
