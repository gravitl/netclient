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

// getRealRangeWindow extracts a /X window from a real range with the same prefix length as virtualRange
// For v1, we map /X -> /X (e.g., 198.18.10.0/24 -> 10.10.0.0/24 from 10.10.0.0/16)
func getRealRangeWindow(realRange net.IPNet, virtualRange net.IPNet) net.IPNet {
	// Get prefix length from virtual range
	virtualPrefixLen, _ := virtualRange.Mask.Size()
	
	// Create a mask with the same prefix length as virtual range
	var mask net.IPMask
	if virtualRange.IP.To4() != nil {
		mask = net.CIDRMask(virtualPrefixLen, 32)
	} else {
		mask = net.CIDRMask(virtualPrefixLen, 128)
	}
	
	// Apply the mask to the real range base IP
	return net.IPNet{
		IP:   realRange.IP.Mask(mask),
		Mask: mask,
	}
}

// getEgressID8 returns first 8 characters of egress ID for chain naming
func getEgressID8(egressID string) string {
	if len(egressID) > 8 {
		return egressID[:8]
	}
	return egressID
}

// getConntrackZone returns a conntrack zone ID based on egress ID hash
func getConntrackZone(egressID string) uint16 {
	// Simple hash to get a zone ID between 100-65535
	hash := 0
	for _, c := range egressID {
		hash = hash*31 + int(c)
	}
	zone := (hash % 64535) + 100 // Range 100-65535
	if zone < 100 {
		zone = 100
	}
	return uint16(zone)
}
