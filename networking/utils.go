package networking

import (
	"net"

	"github.com/gravitl/netclient/config"
)

// IpBelongsToInterface - function to check if an IP belongs to any network interface
func IpBelongsToInterface(ip net.IP) bool {

	for _, iface := range config.Netclient().Interfaces {
		if iface.Address.Contains(ip) {
			return true
		}
	}
	return false
}
