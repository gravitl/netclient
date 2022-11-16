package wireguard

import (
	"net"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// NCIface.Create - makes a new Wireguard interface and sets given addresses
func (nc *NCIface) Create() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()

	WintunStaticRequestedGUID, _ := windows.GenerateGUID()
	adapter, err := driver.CreateAdapter(nc.Settings.Interface, "WireGuard", &WintunStaticRequestedGUID)
	if err != nil {
		return err
	}
	nc.Iface = adapter
	luid := adapter.LUID()
	err = adapter.SetAdapterState(driver.AdapterStateUp)
	if err != nil {
		return err
	}
	state, _ := luid.GUID()
	return nc.applyAddrs(luid)
}

func (nc *NCIface) applyAddrs(luid winipcfg.LUID) error {

	err := luid.SetIPAddresses([]net.IPNet{{nc.Settings.Address.IP, nc.Settings.NetworkRange.Mask}})
	if err != nil {
		return err
	}

	return nil
}
