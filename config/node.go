// Package config provides functions for reading the config.
package config

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"gopkg.in/yaml.v3"
)

// NodeMap is an in memory map of the all nodes indexed by network name
type NodeMap map[string]Node

// Nodes provides a map of node configurations indexed by network name
var Nodes NodeMap

// NodeLockFile is name of lockfile for controlling access to node config file on disk
const NodeLockfile = "netclient-nodes.lck"

// Node provides configuration of a node
type Node struct {
	models.CommonNode
}

// ReadNodeConfig reads node configuration from disk
func ReadNodeConfig() error {
	lockfile := filepath.Join(os.TempDir(), NodeLockfile)
	file := GetNetclientPath() + "nodes.yml"
	if err := Lock(lockfile); err != nil {
		return err
	}
	defer Unlock(lockfile)
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	for k := range Nodes {
		delete(Nodes, k)
	}
	if err := yaml.NewDecoder(f).Decode(&Nodes); err != nil {
		return err
	}
	return nil
}

// GetNodes returns a copy of the NodeMap
func GetNodes() NodeMap {
	return Nodes
}

// GetNode returns returns the node configuation of the specified network name
func GetNode(k string) Node {
	if node, ok := Nodes[k]; ok {
		return node
	}
	return Node{}
}

// SetNodes - sets server nodes in client config
func SetNodes(nodes []models.Node) {
	Nodes = make(NodeMap)
	for _, node := range nodes {
		Nodes[node.Network] = Node{
			CommonNode: node.CommonNode,
		}
	}
}

// UpdateNodeMap updates the in memory nodemap for the specified network
func UpdateNodeMap(k string, value Node) {
	Nodes[k] = value
}

// DeleteNode deletes the node from the nodemap for the specified network
func DeleteNode(k string) {
	delete(Nodes, k)
}

// PrimaryAddress returns the primary address of a node
func (node *Node) PrimaryAddress() net.IPNet {
	if node.Address.IP != nil {
		return node.Address
	}
	return node.Address6
}

// WriteNodeConfig writes the node map to disk
func WriteNodeConfig() error {
	lockfile := filepath.Join(os.TempDir(), NodeLockfile)
	file := GetNetclientPath() + "nodes.yml"
	if _, err := os.Stat(file); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(GetNetclientPath(), os.ModePerm); err != nil {
				return err
			}
			if err := os.Chmod(GetNetclientPath(), 0775); err != nil {
				logger.Log(0, "error setting permissions on "+GetNetclientPath(), err.Error())
			}
		} else if err != nil {
			return err
		}
	}
	if err := Lock(lockfile); err != nil {
		return err
	}
	defer Unlock(lockfile)
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
	if err != nil {
		return err
	}
	defer f.Close()
	err = yaml.NewEncoder(f).Encode(Nodes)
	if err != nil {
		return err
	}
	return f.Sync()
}

// ConvertNode accepts a netmaker node struct and converts to the structs used by netclient
func ConvertNode(nodeGet *models.NodeGet) *Node {
	netmakerNode := nodeGet.Node
	// server := GetServer(netmakerNode.Server)
	// if server == nil {
	// server = ConvertServerCfg(nodeGet.ServerConfig)
	// }
	var node Node
	node.ID = nodeGet.Node.ID
	// n.Name = s.Name
	node.Network = netmakerNode.Network
	// node.Password = netmakerNode.Password
	node.NetworkRange = nodeGet.Node.NetworkRange
	node.NetworkRange6 = nodeGet.Node.NetworkRange6
	// n.Interface = s.Interface
	node.Server = netmakerNode.Server
	node.Connected = nodeGet.Node.Connected
	// node.MacAddress, _ = net.ParseMAC(netmakerNode.MacAddress)
	node.Address = nodeGet.Node.Address
	node.Address6 = nodeGet.Node.Address6
	node.Action = netmakerNode.Action
	node.IsEgressGateway = nodeGet.Node.IsEgressGateway
	node.IsIngressGateway = nodeGet.Node.IsIngressGateway
	node.DNSOn = nodeGet.Node.DNSOn
	// node.Peers = nodeGet.Peers
	// add items not provided by server
	return &node
}

// ConvertToNetmakerNode converts a netclient node to a netmaker node
func ConvertToNetmakerNode(node *Node, server *Server, host *Config) *models.LegacyNode {
	var netmakerNode models.LegacyNode
	netmakerNode.ID = node.ID.String()
	netmakerNode.OS = host.OS
	// netmakerNode.HostID = server.MQID.String()
	netmakerNode.Name = host.Name
	netmakerNode.Network = node.Network
	netmakerNode.Password = host.HostPass
	netmakerNode.AccessKey = server.AccessKey
	netmakerNode.NetworkSettings.AddressRange = node.NetworkRange.String()
	netmakerNode.NetworkSettings.AddressRange6 = node.NetworkRange6.String()
	netmakerNode.Interface = ncutils.GetInterfaceName()
	netmakerNode.Interfaces = host.Interfaces
	netmakerNode.Server = node.Server
	netmakerNode.TrafficKeys.Mine = host.TrafficKeyPublic
	netmakerNode.TrafficKeys.Server = server.TrafficKey
	// only send ip
	netmakerNode.Endpoint = host.EndpointIP.String()
	netmakerNode.Connected = FormatBool(node.Connected)
	netmakerNode.MacAddress = host.MacAddress.String()
	netmakerNode.ListenPort = int32(host.ListenPort)
	// only send ip
	if node.Address.IP == nil {
		netmakerNode.Address = ""
	} else {
		netmakerNode.Address = node.Address.IP.String()
	}
	if node.Address6.IP == nil {
		netmakerNode.Address6 = ""
	} else {
		netmakerNode.Address6 = node.Address6.IP.String()
	}
	netmakerNode.LocalListenPort = int32(host.ListenPort)
	netmakerNode.MTU = int32(host.MTU)
	netmakerNode.PublicKey = host.PublicKey.String()
	netmakerNode.Action = node.Action
	netmakerNode.IsEgressGateway = FormatBool(node.IsEgressGateway)
	netmakerNode.IsIngressGateway = FormatBool(node.IsIngressGateway)
	netmakerNode.IsStatic = FormatBool(host.IsStatic)
	netmakerNode.DNSOn = FormatBool(node.DNSOn)

	return &netmakerNode
}

// ToIPNet parses a cidr string and returns a net.IPNet
func ToIPNet(cidr string) net.IPNet {
	_, response, err := net.ParseCIDR(cidr)
	if err != nil {
		return net.IPNet{}
	}
	return *response
}

// ToUDPAddr parses and ip address string to return a pointer to net.UDPAddr
func ToUDPAddr(address string) *net.UDPAddr {
	addr, _ := net.ResolveUDPAddr("udp", address)
	return addr
}

// ParseAccessToken - decodes base64 encoded access token
func ParseAccessToken(token string) (*models.AccessToken, error) {
	tokenbytes, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		logger.Log(0, "error decoding token", err.Error())
		return nil, err
	}
	var accesstoken models.AccessToken
	if err := json.Unmarshal(tokenbytes, &accesstoken); err != nil {
		logger.Log(0, "error decoding token", err.Error())
		return nil, err
	}
	return &accesstoken, nil
}

// ModPort - Change Node Port if ListenPort is not free
func ModPort(host *Config) error {
	var err error
	host.ListenPort, err = ncutils.GetFreePort(host.ListenPort)
	return err
}

// FormatBool converts a boolean to a [yes|no] string
func FormatBool(b bool) string {
	s := "no"
	if b {
		s = "yes"
	}
	return s
}

// ParseBool parses a [yes|no] string to boolean value
func ParseBool(s string) bool {
	b := false
	if s == "yes" {
		b = true
	}
	return b
}
