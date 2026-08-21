//go:build linux || darwin || freebsd || windows
// +build linux darwin freebsd windows

package wireguard

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gravitl/netclient/config"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
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
// Atomic so callers holding wgMutex (e.g. Configure → ApplyAddrs) can read safely.
var userspaceWGActive atomic.Bool

// UserspaceWGActive reports whether the current netmaker iface is userspace WireGuard.
func UserspaceWGActive() bool {
	return userspaceWGActive.Load()
}

func (nc *NCIface) createUserSpaceWG() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()

	prepareUserspaceTUN(nc)

	// wintun.CreateAdapter panics if wintun.dll cannot be loaded (Windows).
	var tunIface tun.Device
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("userspace TUN create panic (is wintun.dll installed?): %v", r)
			}
		}()
		tunIface, err = tun.CreateTUN(nc.Name, config.Netclient().MTU)
	}()
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
	userspaceWGActive.Store(true)
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

func (nc *NCIface) closeUserspaceWg() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()
	listenPort := 0
	if cfg := config.Netclient(); cfg != nil {
		listenPort = cfg.ListenPort
	}
	fmt.Println("[listen-port-debug] closeUserspaceWg: start",
		"iface=", nc.Name, "listenPort=", listenPort)
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
		closeStart := time.Now()
		go func(dev *device.Device) {
			dev.Close()
			close(done)
		}(tunDevice)
		tunDevice = nil
		select {
		case <-done:
			fmt.Println("[listen-port-debug] closeUserspaceWg: Device.Close done",
				"elapsed=", time.Since(closeStart),
				"portFree=", portFreeDebug(listenPort))
		case <-time.After(15 * time.Second):
			fmt.Println("[listen-port-debug] closeUserspaceWg: Device.Close TIMEOUT",
				"elapsed=", time.Since(closeStart),
				"portFree=", portFreeDebug(listenPort))
			slog.Error("userspace WireGuard Device.Close timed out; continuing shutdown")
		}
	} else {
		fmt.Println("[listen-port-debug] closeUserspaceWg: tunDevice was nil")
	}
	relayBindMu.Lock()
	relayBind = nil
	relayBindMu.Unlock()
	userspaceWGActive.Store(false)

	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
	case <-time.After(3 * time.Second):
		fmt.Println("[listen-port-debug] closeUserspaceWg: UAPI accept loop wait TIMEOUT")
		slog.Warn("userspace WireGuard UAPI accept loop wait timed out")
	}

	// Ensure the previous UDP listen port is released before callers run GetFreePort.
	if listenPort > 0 {
		waitStart := time.Now()
		ok := waitUDPPortFree(listenPort, 5*time.Second)
		fmt.Println("[listen-port-debug] closeUserspaceWg: after port wait",
			"port=", listenPort, "free=", ok, "waited=", time.Since(waitStart))
		if !ok {
			slog.Warn("WireGuard UDP listen port still busy after Device.Close", "port", listenPort)
		}
	}

	slog.Debug("Closed userspace WireGuard interface", "interface", nc.Name)

	return nil
}

func portFreeDebug(port int) bool {
	if port <= 0 {
		return true
	}
	c, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func waitUDPPortFree(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		c, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
		if err == nil {
			_ = c.Close()
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}
