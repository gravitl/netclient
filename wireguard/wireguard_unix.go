//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package wireguard

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

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

// userspaceWGActive is true while a userspace Device from createUserSpaceWG is live.
// Close must consult this — not relayTCPUserspaceNeeded() — because disable flips the
// desired mode before iface.Close(); using the desired flag skips Device.Close and
// leaves UAPI hung (wg show blocks forever).
var userspaceWGActive bool

// UserspaceWGActive reports whether the current netmaker iface is userspace WireGuard.
func UserspaceWGActive() bool {
	wgMutex.Lock()
	defer wgMutex.Unlock()
	return userspaceWGActive
}

func (nc *NCIface) createUserSpaceWG() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()

	tunIface, err := tun.CreateTUN(nc.Name, config.Netclient().MTU)
	if err != nil {
		return err
	}
	nc.Iface = tunIface
	var bind conn.Bind
	if relayTCPUserspaceNeeded() {
		rb := newRelayTCPBind(conn.NewDefaultBind())
		relayBindMu.Lock()
		relayBind = rb
		relayBindMu.Unlock()
		bind = rb
	} else {
		relayBindMu.Lock()
		relayBind = nil
		relayBindMu.Unlock()
		bind = conn.NewDefaultBind()
	}
	tunDevice = device.NewDevice(tunIface, bind, device.NewLogger(device.LogLevelSilent, "[netclient] "))
	err = tunDevice.Up()
	if err != nil {
		return err
	}
	uapi, err = getUAPIByInterface(nc.Name)
	if err != nil {
		return err
	}
	userspaceWGActive = true
	wg.Add(1)
	go func() {
		defer wg.Done()
		dev := tunDevice
		listener := uapi
		for {
			if dev == nil || listener == nil {
				return
			}
			select {
			case <-dev.Wait():
				slog.Debug("tunDevice.Wait() returned")
				return
			default:
				uapiConn, uapiErr := listener.Accept()
				if uapiErr != nil {
					// Listener closed or device shutting down — exit instead of spinning.
					select {
					case <-dev.Wait():
						return
					default:
						slog.Debug("uapi error:", "error", uapiErr)
						return
					}
				}
				go dev.IpcHandle(uapiConn)
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

	// Belt-and-suspenders if caller skipped StopAllTCPUplink.
	PrepareUserspaceTeardown()
	// Unblock TCP ReceiveFunc before Device.Close (closes inbound chan once).
	closeRelayTCPInbound()

	// Unblock UAPI Accept before Device.Close so the accept loop can observe Wait().
	if uapi != nil {
		_ = uapi.Close()
		uapi = nil
	}
	if tunDevice != nil {
		done := make(chan struct{})
		go func(dev *device.Device) {
			dev.Close()
			close(done)
		}(tunDevice)
		tunDevice = nil
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			slog.Error("userspace WireGuard Device.Close timed out; continuing shutdown")
		}
	}
	relayBindMu.Lock()
	relayBind = nil
	relayBindMu.Unlock()
	userspaceWGActive = false

	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
	case <-time.After(3 * time.Second):
		slog.Warn("userspace WireGuard UAPI accept loop wait timed out")
	}

	slog.Debug("Closed userspace WireGuard interface", "interface", nc.Name)

	return nil
}

func isEconnRefused(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && errors.Is(errno, syscall.ECONNREFUSED)
}
