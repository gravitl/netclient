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
	// newNode.PublicKey != currentNode.PublicKey ||
	if newNode.Address.IP.String() != currentNode.Address.IP.String() ||
		newNode.Address6.IP.String() != currentNode.Address6.IP.String() ||
		newNode.IsEgressGateway != currentNode.IsEgressGateway ||
		newNode.IsIngressGateway != currentNode.IsIngressGateway ||
		// newNode.IsRelay != currentNode.IsRelay ||
		// newNode.UDPHolePunch != currentNode.UDPHolePunch ||
		// newNode.ListenPort != currentNode.ListenPort ||
		// newNode.MTU != currentNode.MTU ||
		newNode.DNSOn != currentNode.DNSOn ||
		newNode.Connected != currentNode.Connected {
		return true
	}

	// multi-comparison statements
	// if newNode.IsEgressGateway  {
	// if len(currentNode.EgressGatewayRanges) != len(newNode.EgressGatewayRanges) {
	// return true
	// }
	// for _, address := range newNode.EgressGatewayRanges {
	// if !StringSliceContains(currentNode.EgressGatewayRanges, address) {
	// return true
	// }
	// }
	// }

	// if newNode.IsRelay {
	//	if len(currentNode.RelayAddrs) != len(newNode.RelayAddrs) {
	//		return true
	//	}
	//	for _, address := range newNode.RelayAddrs {
	//		if !StringSliceContains(currentNode.RelayAddrs, address) {
	//			return true
	//		}
	//	}
	// }

	// for _, address := range newNode.AllowedIPs {
	//	if !StringSliceContains(currentNode.AllowedIPs, address) {
	//		return true
	//	}
	// }
	return false
}
