package wireguard

import (
	"fmt"
	"net/netip"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// NCIface.Create - makes a new Wireguard interface and sets given addresses
func (nc *NCIface) Create() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()

	windowsGUID, err := windows.GenerateGUID()
	if err != nil {
		return err
	}
	logger.Log(3, "creating Windows tunnel")
	adapter, err := driver.CreateAdapter(ncutils.GetInterfaceName(), "WireGuard", &windowsGUID)
	if err != nil {
		return err
	}
	logger.Log(3, "created Windows tunnel")
	nc.Iface = adapter
	luid := adapter.LUID()
	err = adapter.SetAdapterState(driver.AdapterStateUp)
	if err != nil {
		return err
	}
	logger.Log(3, "set adapter state")

	return nc.applyAddrs(&luid)
}

// NCIface.ApplyAddrs - applies addresses to windows tunnel ifaces, unused currently
func (nc *NCIface) ApplyAddrs() error {
	return nil
}

func (nc *NCIface) Close() {
	err := nc.Iface.Close()
	if err != nil {
		logger.Log(0, "error closing netclient interface -", err.Error())
	}
}

func (nc *NCIface) applyAddrs(luid *winipcfg.LUID) error {

	if len(nc.Addresses) == 0 {
		return fmt.Errorf("no addresses provided")
	}

	prefixAddrs := []netip.Prefix{}
	for i := range nc.Addresses {
		maskSize, _ := nc.Addresses[i].Network.Mask.Size()
		logger.Log(0, "appending address", fmt.Sprintf("%s/%d to nm interface", nc.Addresses[i].IP.String(), maskSize))
		addr, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", nc.Addresses[i].IP.String(), maskSize))
		if err == nil {
			prefixAddrs = append(prefixAddrs, addr)
		} else {
			logger.Log(0, fmt.Sprintf("failed to append ip to Netclient adapter %v", err))
		}
	}

	err := luid.SetIPAddresses(prefixAddrs)
	if err != nil {
		return err
	}

	return nil
}
