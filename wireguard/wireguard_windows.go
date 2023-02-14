package wireguard

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver"
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
	return adapter.SetAdapterState(driver.AdapterStateUp)
}

// NCIface.ApplyAddrs - applies addresses to windows tunnel ifaces, unused currently
func (nc *NCIface) ApplyAddrs() error {
	adapter := nc.Iface
	prefixAddrs := []netip.Prefix{}
	egressRanges := []ifaceAddress{}
	var egressRoute *ifaceAddress
	for i := range nc.Addresses {
		if !nc.Addresses[i].AddRoute {
			maskSize, _ := nc.Addresses[i].Network.Mask.Size()
			logger.Log(1, "appending address", fmt.Sprintf("%s/%d to nm interface", nc.Addresses[i].IP.String(), maskSize))
			addr, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", nc.Addresses[i].IP.String(), maskSize))
			if err == nil {
				prefixAddrs = append(prefixAddrs, addr)
			} else {
				logger.Log(0, fmt.Sprintf("failed to append ip to Netclient adapter %v", err))
			}
			if egressRoute == nil {
				egressRoute = &nc.Addresses[i]
			}
		} else {
			egressRanges = append(egressRanges, nc.Addresses[i])
		}
	}

	if egressRoute != nil && len(egressRanges) > 0 {
		for i := range egressRanges {
			maskSize, _ := egressRanges[i].Network.Mask.Size()
			mask := net.IP(egressRanges[i].Network.Mask)
			logger.Log(1, "appending egress range", fmt.Sprintf("%s/%d to nm interface", egressRanges[i].IP.String(), maskSize))
			cmd := fmt.Sprintf("route -p add %s MASK %v %s", egressRanges[i].IP.String(),
				mask,
				egressRoute.IP.String())
			_, err := ncutils.RunCmd(cmd, false)
			if err != nil {
				logger.Log(0, "failed to apply egress range", egressRanges[i].IP.String())
			}
		}
	}

	return adapter.(*driver.Adapter).LUID().SetIPAddresses(prefixAddrs)
}

// NCIface.Close - closes the managed WireGuard interface
func (nc *NCIface) Close() {
	err := nc.Iface.Close()
	if err != nil {
		logger.Log(0, "error closing netclient interface -", err.Error())
	}

	// clean up egress range routes
	for i := range nc.Addresses {
		if nc.Addresses[i].AddRoute {
			maskSize, _ := nc.Addresses[i].Network.Mask.Size()
			logger.Log(1, "removing egress range", fmt.Sprintf("%s/%d from nm interface", nc.Addresses[i].IP.String(), maskSize))
			cmd := fmt.Sprintf("route delete %s", nc.Addresses[i].IP.String())
			_, err := ncutils.RunCmd(cmd, false)
			if err != nil {
				logger.Log(0, "failed to remove egress range", nc.Addresses[i].IP.String())
			}
		}
	}
}

// NCIface.SetMTU - sets the MTU of the windows WireGuard Iface adapter
func (nc *NCIface) SetMTU() error {
	// TODO figure out how to change MTU of adapter
	return nil
}
