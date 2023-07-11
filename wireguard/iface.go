// Package wireguard manipulates wireguard interfaces
package wireguard

import (
	"net"
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
