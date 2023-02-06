package router

import (
	"errors"
	"net"
	"net/netip"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logic"
)

// getInterfaceName addr is CIDR notation (198.0.0.1/24) returns matching interface
func getInterfaceName(addr string) (string, error) {
	var interfaceName string
	var err error
	ip, _, err := net.ParseCIDR(addr)
	if err != nil {
		return interfaceName, err
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return interfaceName, err
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			// check if gw range is in cidr range of the interface
			addrIPNet := config.ToIPNet(a.String())
			if isAddrIpv4(addrIPNet.String()) {
				addrIPNet.Mask = net.CIDRMask(8, 32)
			} else {
				addrIPNet.Mask = net.CIDRMask(64, 128)
			}
			normCIDR, err := logic.NormalizeCIDR(addrIPNet.String())
			if err == nil {
				if logic.IsAddressInCIDR(ip, normCIDR) {
					return i.Name, nil
				}
			}

		}
	}
	return interfaceName, errors.New("interface not found for addr: " + addr)
}

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
