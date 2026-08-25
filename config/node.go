// Package config provides functions for reading the config.
package config

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/gravitl/netmaker/models"
)

var nodeMutex sync.RWMutex

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

// AnyNodeConnected reports whether any network is locally marked connected.
func AnyNodeConnected() bool {
	nodeMutex.RLock()
	defer nodeMutex.RUnlock()
	for _, node := range Nodes {
		if node.Connected {
			return true
		}
	}
	return false
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
	nodeMutex.Lock()
	defer nodeMutex.Unlock()
	return WriteJSONAtomic(
		filepath.Join(GetNetclientPath(), "nodes.json"),
		Nodes,
		filepath.Join(os.TempDir(), NodeLockfile),
		0700,
	)
}

// ToIPNet parses a cidr string and returns a net.IPNet
func ToIPNet(cidr string) net.IPNet {
	_, response, err := net.ParseCIDR(cidr)
	if err != nil {
		return net.IPNet{}
	}
	return *response
}
