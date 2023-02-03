package router

import (
	"errors"
	"net"
	"net/netip"

	"github.com/gravitl/netmaker/logic"
)

// gets the interface name for the network addr (198.0.0.1/24)
func getInterfaceName(addr string) (string, error) {
	var interfaceName string
	var err error
	ifaces, err := net.Interfaces()
	if err != nil {
		return interfaceName, err
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			prefix, err := netip.ParsePrefix(a.String())
			if err == nil && logic.IsAddressInCIDR(net.ParseIP(prefix.Addr().String()), addr) {
				return i.Name, nil
			}

		}
	}
	return interfaceName, errors.New("interface not found for addr: " + addr)
}

// addr - CIDR notation (198.0.0.1/24) return if ipnet is ipv4 or ipv6
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
