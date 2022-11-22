// Package config provides functions for reading the config.
package config

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v3"
)

// Nodes provides a map of node configurations indexed by network name
var Nodes map[string]Node

// NodeLockFile is name of lockfile for controlling access to node config file on disk
const NodeLockfile = "netclient-nodes.lck"

// Node provides configuration of a node
type Node struct {
	ID                  string
	Network             string
	NetworkRange        net.IPNet
	NetworkRange6       net.IPNet
	InternetGateway     *net.UDPAddr
	Server              string
	Connected           bool
	EndpointIP          net.IP
	Address             net.IPNet
	Address6            net.IPNet
	PostUp              string
	PostDown            string
	Action              string
	IsServer            bool
	IsLocal             bool
	IsEgressGateway     bool
	IsIngressGateway    bool
	IsStatic            bool
	IsPending           bool
	DNSOn               bool
	IsHub               bool
	PersistentKeepalive int
	Peers               []wgtypes.PeerConfig
}

// ReadNodeConfig - reads node configuration from disk
func ReadNodeConfig() error {
	lockfile := filepath.Join(os.TempDir() + NodeLockfile)
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
	if err := yaml.NewDecoder(f).Decode(&Nodes); err != nil {
		return err
	}
	return nil
}

// PrimaryAddress returns the primary address of a node
func (node *Node) PrimaryAddress() net.IPNet {
	if node.Address.IP != nil {
		return node.Address
	}
	return node.Address6
}

// writeNodeConfiguation writes the node map to disk
func WriteNodeConfig() error {
	lockfile := filepath.Join(os.TempDir() + NodeLockfile)
	file := GetNetclientPath() + "nodes.yml"
	if _, err := os.Stat(file); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(GetNetclientPath(), os.ModePerm)
		} else if err != nil {
			return err
		}
	}
	if err := Lock(lockfile); err != nil {
		return err
	}
	defer Unlock(lockfile)
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
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

// ConvertNode accepts a netmaker node struc and converts to the structs used by netclient
func ConvertNode(nodeGet *models.NodeGet) (*Node, *Server, *Config) {
	host := Netclient
	netmakerNode := nodeGet.Node
	server, ok := Servers[netmakerNode.Network]
	if !ok {
		server = *ConvertServerCfg(&nodeGet.ServerConfig)
	}
	var node Node
	node.ID = netmakerNode.ID
	//n.Name = s.Name
	node.Network = netmakerNode.Network
	//node.Password = netmakerNode.Password
	server.AccessKey = netmakerNode.AccessKey
	node.NetworkRange = ToIPNet(netmakerNode.NetworkSettings.AddressRange)
	node.NetworkRange6 = ToIPNet(netmakerNode.NetworkSettings.AddressRange6)
	node.InternetGateway = ToUDPAddr(netmakerNode.InternetGateway)
	//n.Interface = s.Interface
	node.Server = strings.Replace(netmakerNode.Server, "api.", "", 1)
	server.TrafficKey = netmakerNode.TrafficKeys.Server
	node.EndpointIP = net.ParseIP(netmakerNode.Endpoint)
	node.Connected = ParseBool(netmakerNode.Connected)
	//node.MacAddress, _ = net.ParseMAC(netmakerNode.MacAddress)
	host.ListenPort = int(netmakerNode.ListenPort)
	node.Address.IP = net.ParseIP(netmakerNode.Address)
	node.Address.Mask = node.NetworkRange.Mask
	node.Address6.IP = net.ParseIP(netmakerNode.Address6)
	node.Address6.Mask = node.NetworkRange6.Mask
	host.ListenPort = int(netmakerNode.ListenPort)
	host.LocalAddress = ToIPNet(netmakerNode.LocalAddress)
	host.LocalRange = ToIPNet(netmakerNode.LocalRange)
	host.MTU = int(netmakerNode.MTU)
	node.PersistentKeepalive = int(netmakerNode.PersistentKeepalive)
	host.PublicKey, _ = wgtypes.ParseKey(netmakerNode.PublicKey)
	node.PostUp = netmakerNode.PostUp
	node.PostDown = netmakerNode.PostDown
	node.Action = netmakerNode.Action
	host.UDPHolePunch = ParseBool(netmakerNode.UDPHolePunch)
	node.IsLocal = ParseBool(netmakerNode.IsLocal)
	node.IsEgressGateway = ParseBool(netmakerNode.IsEgressGateway)
	node.IsIngressGateway = ParseBool(netmakerNode.IsIngressGateway)
	node.IsStatic = ParseBool(netmakerNode.IsStatic)
	node.IsPending = ParseBool(netmakerNode.IsPending)
	node.DNSOn = ParseBool(netmakerNode.DNSOn)
	node.IsHub = ParseBool(netmakerNode.IsHub)
	node.Peers = nodeGet.Peers
	//add items not provided by server
	return &node, &server, &host
}

// ConvertToNetmakerNode converts a netclient node to a netmaker node
func ConvertToNetmakerNode(node *Node, server *Server, host *Config) *models.Node {
	var netmakerNode models.Node
	netmakerNode.ID = node.ID
	netmakerNode.OS = Netclient.OS
	netmakerNode.HostID = Servers[node.Server].MQID
	netmakerNode.Name = host.Name
	netmakerNode.Network = node.Network
	netmakerNode.Password = host.NodePassword
	netmakerNode.AccessKey = server.AccessKey
	netmakerNode.NetworkSettings.AddressRange = node.NetworkRange.String()
	netmakerNode.NetworkSettings.AddressRange6 = node.NetworkRange6.String()
	netmakerNode.InternetGateway = ""
	if node.InternetGateway != nil {
		netmakerNode.InternetGateway = node.InternetGateway.IP.String()
	}
	netmakerNode.Interface = host.Interface
	netmakerNode.Server = node.Server
	netmakerNode.TrafficKeys.Mine = Netclient.TrafficKeyPublic
	netmakerNode.TrafficKeys.Server = server.TrafficKey
	//only send ip
	netmakerNode.Endpoint = node.EndpointIP.String()
	netmakerNode.Connected = FormatBool(node.Connected)
	netmakerNode.MacAddress = host.MacAddress.String()
	netmakerNode.ListenPort = int32(host.ListenPort)
	//only send ip
	netmakerNode.Address = node.Address.IP.String()
	if node.Address.IP == nil {
		netmakerNode.Address = ""
	}
	netmakerNode.Address6 = node.Address6.IP.String()
	if node.Address6.IP == nil {
		netmakerNode.Address6 = ""
	}
	netmakerNode.ListenPort = int32(host.ListenPort)
	netmakerNode.LocalAddress = host.LocalAddress.String()
	netmakerNode.LocalRange = host.LocalRange.String()
	netmakerNode.MTU = int32(host.MTU)
	netmakerNode.PersistentKeepalive = int32(node.PersistentKeepalive)
	netmakerNode.PublicKey = host.PublicKey.String()
	netmakerNode.PostUp = node.PostUp
	netmakerNode.PostDown = node.PostDown
	netmakerNode.Action = node.Action
	netmakerNode.UDPHolePunch = FormatBool(host.UDPHolePunch)
	netmakerNode.IsLocal = FormatBool(node.IsLocal)
	netmakerNode.IsEgressGateway = FormatBool(node.IsEgressGateway)
	netmakerNode.IsIngressGateway = FormatBool(node.IsIngressGateway)
	netmakerNode.IsStatic = FormatBool(node.IsStatic)
	netmakerNode.IsPending = FormatBool(node.IsPending)
	netmakerNode.DNSOn = FormatBool(node.DNSOn)
	netmakerNode.IsHub = FormatBool(node.IsHub)
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

// ModPort - Change Node Port if UDP Hole Punching or ListenPort is not free
func ModPort(host *Config) error {
	var err error
	if host.UDPHolePunch {
		host.ListenPort = 0
	} else {
		host.ListenPort, err = ncutils.GetFreePort(host.ListenPort)
	}
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
