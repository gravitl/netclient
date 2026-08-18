//go:build windows
// +build windows

package wireguard

import (
	"net"

	"golang.zx2c4.com/wireguard/ipc"
)

func getUAPIByInterface(iface string) (net.Listener, error) {
	// Windows UAPI is a named pipe; there is no UAPIOpen.
	return ipc.UAPIListen(iface)
}
