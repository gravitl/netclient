// Package config provides functions for reading the config.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/sasha-s/go-deadlock"
)

var nodeMutex = &deadlock.RWMutex{}

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
	nodesI := make(NodeMap)
	var err error
	defer func() {
		if err == nil {
			nodeMutex.Lock()
			Nodes = make(NodeMap)
			Nodes = nodesI
			nodeMutex.Unlock()
		}
	}()
	lockfile := filepath.Join(os.TempDir(), NodeLockfile)
	file := GetNetclientPath() + "nodes.json"
	if err = Lock(lockfile); err != nil {
		return err
	}
	defer Unlock(lockfile)
	f, ferr := os.Open(file)
	if ferr != nil {
		err = ferr
		return err
	}
	defer f.Close()
	if err = json.NewDecoder(f).Decode(&nodesI); err != nil {
		return err
	}
	return nil
}

// GetNodes returns a copy of the NodeMap
func GetNodes() NodeMap {
	nodeMutex.RLock()
	defer nodeMutex.RUnlock()
	return Nodes
}

// GetNode returns returns the node configuation of the specified network name
func GetNode(k string) Node {
	nodeMutex.RLock()
	defer nodeMutex.RUnlock()
	if node, ok := Nodes[k]; ok {
		return node
	}
	return Node{}
}

// SetNodes - sets server nodes in client config
func SetNodes(nodes []models.Node) {
	nodeMutex.Lock()
	defer nodeMutex.Unlock()
	Nodes = make(NodeMap)
	for _, node := range nodes {
		Nodes[node.Network] = Node{
			CommonNode: node.CommonNode,
		}
	}
}

// DeleteNodes - removes all nodes
func DeleteNodes() {
	nodeMutex.Lock()
	defer nodeMutex.Unlock()
	Nodes = make(NodeMap)
}

// UpdateNodeMap updates the in memory nodemap for the specified network
func UpdateNodeMap(k string, value Node) {
	nodeMutex.Lock()
	defer nodeMutex.Unlock()
	Nodes[k] = value
}

// DeleteNode deletes the node from the nodemap for the specified network
func DeleteNode(k string) {
	nodeMutex.Lock()
	defer nodeMutex.Unlock()
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
	configDir := GetNetclientPath()
	file := filepath.Join(configDir, "nodes.json")
	tmpFile := file + ".tmp"
	backupFile := file + ".bak"

	// Ensure config directory exists
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
		if err := os.Chmod(configDir, 0775); err != nil {
			// Just log, not fatal
			logger.Log(0, "error setting permissions on "+configDir, err.Error())
		}
	} else if err != nil {
		return fmt.Errorf("error checking config directory: %w", err)
	}

	// Acquire lock
	if err := Lock(lockfile); err != nil {
		return fmt.Errorf("failed to obtain lockfile: %w", err)
	}
	defer Unlock(lockfile)

	// Open temp file
	f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
	if err != nil {
		return fmt.Errorf("failed to create temp nodes file: %w", err)
	}

	// Get nodes list safely
	nodeMutex.Lock()
	nodesI := Nodes
	nodeMutex.Unlock()

	if nodesI == nil {
		f.Close()
		return errors.New("nodes config is nil")
	}

	// Write JSON
	j := json.NewEncoder(f)
	j.SetIndent("", "    ")
	if err := j.Encode(nodesI); err != nil {
		f.Close()
		return fmt.Errorf("failed to encode nodes config: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("failed to sync nodes config: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Optional delay to release file handle on Windows
	if runtime.GOOS == "windows" {
		time.Sleep(50 * time.Millisecond)
		_ = os.Remove(file) // remove old file to avoid rename issue
	}

	// Remove previous backup if it exists
	_ = os.Remove(backupFile)

	// Backup existing config
	if _, err := os.Stat(file); err == nil {
		if err := os.Rename(file, backupFile); err != nil {
			return fmt.Errorf("failed to backup existing nodes config: %w", err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error checking existing nodes config: %w", err)
	}

	// Rename temp -> final
	if err := os.Rename(tmpFile, file); err != nil {
		return fmt.Errorf("failed to rename temp nodes config: %w", err)
	}

	return nil
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
	//node.DNSOn = nodeGet.Node.DNSOn
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
	//netmakerNode.DNSOn = FormatBool(node.DNSOn)

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
