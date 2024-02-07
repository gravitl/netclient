//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package wireguard

import (
	"net"
	"sync"

	"github.com/gravitl/netclient/config"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

// == private ==

var tunDevice *device.Device
var wg sync.WaitGroup
var uapi net.Listener

func (nc *NCIface) createUserSpaceWG() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()

	tunIface, err := tun.CreateTUN(nc.Name, config.Netclient().MTU)
	if err != nil {
		return err
	}
	nc.Iface = tunIface
	tunDevice = device.NewDevice(tunIface, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "[netclient] "))
	err = tunDevice.Up()
	if err != nil {
		return err
	}
	uapi, err = getUAPIByInterface(nc.Name)
	if err != nil {
		return err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-tunDevice.Wait():
				slog.Debug("tunDevice.Wait() returned")
				return
			default:
				uapiConn, uapiErr := uapi.Accept()
				if uapiErr != nil {
					slog.Debug("uapi error:", "error", uapiErr)
					continue
				}
				go tunDevice.IpcHandle(uapiConn)
			}
		}
	}()
	return nil
}

func getUAPIByInterface(iface string) (net.Listener, error) {
	tunSock, err := ipc.UAPIOpen(iface)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(iface, tunSock)
}

func (nc *NCIface) closeUserspaceWg() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()
	slog.Debug("Closing userspace WireGuard interface", "interface", nc.Name)

	tunDevice.Close()
	uapi.Close()
	wg.Wait()

	slog.Debug("Closed userspace WireGuard interface", "interface", nc.Name)

	return nil
}
