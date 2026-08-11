//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package wireguard

import (
	"net"

	"golang.zx2c4.com/wireguard/ipc"
)

func getUAPIByInterface(iface string) (net.Listener, error) {
	tunSock, err := ipc.UAPIOpen(iface)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(iface, tunSock)
}
