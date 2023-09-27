// Package config provides functions for reading the config.
package config

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v3"

	"github.com/gravitl/netclient/ncutils"
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

// getNodePersistentKeepAlive tries to get the PKA of a node
func GetNodePersistentKeepAlive(
	node *Node,
	getPeerConfig func(net.IP) (wgtypes.PeerConfig, error),
) time.Duration {
	// get peer configs
	pcV4, errV4 := getPeerConfig(node.Address.IP)
	pcV6, errV6 := getPeerConfig(node.Address6.IP)
	// default on err
	if errV4 != nil && errV6 != nil {
		return Netclient().PersistentKeepalive
	}
	// other if err
	if errV4 != nil {
		return *pcV6.PersistentKeepaliveInterval
	}
	if errV6 != nil {
		return *pcV4.PersistentKeepaliveInterval
	}
	// get PKAs
	pkaV4 := *pcV4.PersistentKeepaliveInterval
	pkaV6 := *pcV6.PersistentKeepaliveInterval
	// other if zero
	if pkaV4 != pkaV6 {
		if pkaV4 != 0 {
			return pkaV6
		}
		if pkaV6 != 0 {
			return pkaV4
		}
	}
	return pkaV4 // or pkaV6, they're the same
}

// getPKAFromHostPeer returns the PKA of a node by retrieving its peer config with config.GetHostPeer
func GetNodePKA(node *Node) time.Duration {
	return GetNodePersistentKeepAlive(node, GetHostPeer)
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
