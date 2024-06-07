// Package wireguard manipulates wireguard interfaces
package wireguard

import (
	"net"

	"github.com/gravitl/netclient/config"
)

// IfaceExists - return true if you can find the iface
func IfaceExists(ifacename string) bool {
	localnets, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, localnet := range localnets {
		if ifacename == localnet.Name {
			return true
		}
	}
	return false
}

// IfaceDelta - checks if the new node causes an interface change
func IfaceDelta(currentNode *config.Node, newNode *config.Node) bool {
	// single comparison statements
	if newNode.Address.IP.String() != currentNode.Address.IP.String() ||
		newNode.Address6.IP.String() != currentNode.Address6.IP.String() ||
		newNode.DNSOn != currentNode.DNSOn ||
		newNode.Connected != currentNode.Connected {
		return true
	}
	return false
}
