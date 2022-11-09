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
	Name                string
	Network             string
	Password            string
	AccessKey           string
	NetworkRange        net.IPNet
	NetworkRange6       net.IPNet
	InternetGateway     *net.UDPAddr
	Interface           string
	Server              string
	Connected           bool
	TrafficKeys         models.TrafficKeys
	TrafficPrivateKey   *[32]byte
	MacAddress          net.HardwareAddr
	Port                int
	EndpointIP          net.IP
	Address             net.IPNet
	Address6            net.IPNet
	ListenPort          int
	LocalAddress        net.IPNet
	LocalRange          net.IPNet
	LocalListenPort     int
	MTU                 int
	PersistentKeepalive int
	PrivateKey          wgtypes.Key
	PublicKey           wgtypes.Key
	PostUp              string
	PostDown            string
	Action              string
	IsServer            bool
	UDPHolePunch        bool
	IsLocal             bool
	IsEgressGateway     bool
	IsIngressGateway    bool
	IsStatic            bool
	IsPending           bool
	DNSOn               bool
	IsHub               bool
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

// ConvertNode accepts a netmaker node struc and converts to a netclient node struct
func ConvertNode(s *models.Node) *Node {
	//pretty.Println(s)
	var n Node
	n.ID = s.ID
	n.Name = s.Name
	n.Network = s.Network
	n.Password = s.Password
	n.AccessKey = s.AccessKey
	n.NetworkRange = ToIPNet(s.NetworkSettings.AddressRange)
	n.NetworkRange6 = ToIPNet(s.NetworkSettings.AddressRange6)
	n.InternetGateway = ToUDPAddr(s.InternetGateway)
	n.Interface = s.Interface
	n.Server = strings.Replace(s.Server, "api.", "", 1)
	n.TrafficKeys = s.TrafficKeys
	n.EndpointIP = net.ParseIP(s.Endpoint)
	n.Connected = ParseBool(s.Connected)
	n.MacAddress, _ = net.ParseMAC(s.MacAddress)
	n.Port = int(s.ListenPort)
	n.Address.IP = net.ParseIP(s.Address)
	n.Address.Mask = n.NetworkRange.Mask
	n.Address6.IP = net.ParseIP(s.Address6)
	n.Address6.Mask = n.NetworkRange6.Mask
	n.ListenPort = int(s.ListenPort)
	n.LocalAddress = ToIPNet(s.LocalAddress)
	n.LocalRange = ToIPNet(s.LocalRange)
	n.MTU = int(s.MTU)
	n.PersistentKeepalive = int(s.PersistentKeepalive)
	n.PublicKey, _ = wgtypes.ParseKey(s.PublicKey)
	n.PostUp = s.PostUp
	n.PostDown = s.PostDown
	n.Action = s.Action
	n.UDPHolePunch = ParseBool(s.UDPHolePunch)
	n.IsLocal = ParseBool(s.IsLocal)
	n.IsEgressGateway = ParseBool(s.IsEgressGateway)
	n.IsIngressGateway = ParseBool(s.IsIngressGateway)
	n.IsStatic = ParseBool(s.IsStatic)
	n.IsPending = ParseBool(s.IsPending)
	n.DNSOn = ParseBool(s.DNSOn)
	n.IsHub = ParseBool(s.IsHub)
	return &n
}

// ConverttoOldNode converts a netclient node to a netmaker node
func ConvertToOldNode(n *Node) *models.Node {
	var s models.Node
	s.ID = n.ID
	s.OS = Netclient.OS
	s.HostID = Servers[n.Server].MQID
	s.Name = n.Name
	s.Network = n.Network
	s.Password = n.Password
	s.AccessKey = n.AccessKey
	s.NetworkSettings.AddressRange = n.NetworkRange.String()
	s.NetworkSettings.AddressRange6 = n.NetworkRange6.String()
	s.InternetGateway = ""
	if n.InternetGateway != nil {
		s.InternetGateway = n.InternetGateway.IP.String()
	}
	s.Interface = n.Interface
	s.Server = n.Server
	s.TrafficKeys = n.TrafficKeys
	//only send ip
	s.Endpoint = n.EndpointIP.String()
	s.Connected = FormatBool(n.Connected)
	s.MacAddress = n.MacAddress.String()
	s.ListenPort = int32(n.ListenPort)
	//only send ip
	s.Address = n.Address.IP.String()
	s.Address6 = n.Address6.IP.String()
	s.ListenPort = int32(n.ListenPort)
	s.LocalAddress = n.LocalAddress.String()
	s.LocalRange = n.LocalRange.String()
	s.MTU = int32(n.MTU)
	s.PersistentKeepalive = int32(s.PersistentKeepalive)
	s.PublicKey = n.PublicKey.String()
	s.PostUp = n.PostUp
	s.PostDown = n.PostDown
	s.Action = n.Action
	s.UDPHolePunch = FormatBool(n.UDPHolePunch)
	s.IsLocal = FormatBool(n.IsLocal)
	s.IsEgressGateway = FormatBool(n.IsEgressGateway)
	s.IsIngressGateway = FormatBool(n.IsIngressGateway)
	s.IsStatic = FormatBool(n.IsStatic)
	s.IsPending = FormatBool(n.IsPending)
	s.DNSOn = FormatBool(n.DNSOn)
	s.IsHub = FormatBool(n.IsHub)
	return &s
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
func ModPort(node *Node) error {
	var err error
	if node.UDPHolePunch {
		node.ListenPort = 0
	} else {
		node.ListenPort, err = ncutils.GetFreePort(node.ListenPort)
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
