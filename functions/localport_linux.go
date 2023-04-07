package functions

import (
	"errors"
	"fmt"
	"net"

	"github.com/gravitl/netclient/ncutils"
	"github.com/vishvananda/netlink"
)

func getDefaultInterface() (string, error) {
	dest := net.ParseIP("1.1.1.1")
	// routes[0] will be default route
	routes, err := netlink.RouteGet(dest)
	if err != nil {
		return "", err
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Index == routes[0].LinkIndex {
			if iface.Name == ncutils.GetInterfaceName() {
				return "", fmt.Errorf("current default gateway is netmaker")
			}
			return iface.Name, err
		}
	}
	return "", errors.New("default gateway not found")
}
