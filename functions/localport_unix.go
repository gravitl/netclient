//go:build freebsd || darwin
// +build freebsd darwin

package functions

import (
	"errors"
	"net"

	"golang.org/x/net/route"
)

func getDefaultInterface() (string, error) {
	var defaultRoute = [4]byte{0, 0, 0, 0}
	var index int
	rib, _ := route.FetchRIB(0, route.RIBTypeRoute, 0)
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return "", err
	}
	for _, message := range messages {
		route_message := message.(*route.RouteMessage)
		addresses := route_message.Addrs
		var destination, gateway *route.Inet4Addr
		ok := false
		if destination, ok = addresses[0].(*route.Inet4Addr); !ok {
			continue
		}
		if gateway, ok = addresses[1].(*route.Inet4Addr); !ok {
			continue
		}
		if destination == nil || gateway == nil {
			continue
		}
		if destination.IP == defaultRoute {
			index = route_message.Index
			break
		}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Index == index {
			return iface.Name, nil
		}
	}
	return "", errors.New("defautl gw not found")
}
