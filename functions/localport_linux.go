package functions

import (
	"errors"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
)

const (
	TESTIPV4 = "1.1.1.1"
	TESTIPV6 = "2606:4700:4700::1111"
)

func getDefaultInterface() (string, error) {
	dest := net.ParseIP(TESTIPV4)
	// routes[0] will be default route
	routes, err := netlink.RouteGet(dest)
	if err != nil {
		if !strings.Contains(err.Error(), "network is unreachable") {
			return "", err
		}
		//if ipv4 address is unreachable, try ipv6 address
		dest = net.ParseIP(TESTIPV6)
		// routes[0] will be default route
		routes, err = netlink.RouteGet(dest)
		if err != nil {
			return "", err
		}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Index == routes[0].LinkIndex {
			return iface.Name, err
		}
	}
	return "", errors.New("default gateway not found")
}
