package firewall

import (
	"net"
	"net/netip"
	"strings"
)

// isAddrIpv4 - CIDR notation (198.0.0.1/24) return if ipnet is ipv4 or ipv6
func isAddrIpv4(addr string) bool {
	isIpv4 := true
	prefix, err := netip.ParsePrefix(addr)
	if err != nil {
		return isIpv4
	}

	if prefix.Addr().Unmap().Is6() {
		isIpv4 = false
	}
	return isIpv4
}

// isDockerInterface - checks if an interface is a Docker network interface
func isDockerInterface(ifaceName string) bool {
	// Docker interfaces typically start with "docker" or "br-" (bridge)
	return strings.HasPrefix(ifaceName, "docker") || strings.HasPrefix(ifaceName, "br-")
}

// GetLocalIPs retrieves all local IPs (IPv4 and IPv6) on the machine.
func GetLocalIPs() ([]net.IP, error) {
	var localIPs []net.IP
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err == nil {
				localIPs = append(localIPs, ip)
			}
		}
	}
	return localIPs, nil
}
