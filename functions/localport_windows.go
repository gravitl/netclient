package functions

import (
	"net"

	"golang.org/x/net/nettest"
)

func getDefaultInterface() (string, error) {

	iface, err := nettest.RoutedInterface("ip", net.FlagUp|net.FlagBroadcast)
	if err != nil {
		return "", err
	}
	return iface.Name, err
}
