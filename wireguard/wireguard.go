package wireguard

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/local"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// ApplyConf - applys a conf on disk to WireGuard interface
func ApplyConf(node *config.Node, confPath string) {
	os := runtime.GOOS
	if ncutils.IsLinux() && !ncutils.HasWgQuick() {
		os = "nowgquick"
	}
	switch os {
	case "windows":
		ApplyWindowsConf(confPath, node.Interface, node.Connected)
	case "nowgquick":
		ApplyWithoutWGQuick(node, node.Interface, confPath, node.Connected)
	default:
		ApplyWGQuickConf(confPath, node.Interface, node.Connected)
	}

	if !node.IsServer {
		if node.NetworkRange.IP != nil {
			local.SetCIDRRoute(node.Interface, &node.NetworkRange)
		}
		if node.NetworkRange6.IP != nil {
			local.SetCIDRRoute(node.Interface, &node.NetworkRange6)
		}
	}
}

// ApplyWGQuickConf - applies wg-quick commands if os supports
func ApplyWGQuickConf(confPath, ifacename string, isConnected bool) error {
	_, err := os.Stat(confPath)
	if err != nil {
		logger.Log(0, confPath+" does not exist "+err.Error())
		return err
	}
	if ncutils.IfaceExists(ifacename) {
		ncutils.RunCmd("wg-quick down "+confPath, true)
	}
	if !isConnected {
		return nil
	}
	_, err = ncutils.RunCmd("wg-quick up "+confPath, true)

	return err
}

// RemoveConfGraceful - Run remove conf and wait for it to actually be gone before proceeding
func RemoveConfGraceful(ifacename string) {
	// ensure you clear any existing interface first
	wgclient, err := wgctrl.New()
	if err != nil {
		logger.Log(0, "could not create wgclient")
		return
	}
	defer wgclient.Close()
	d, _ := wgclient.Device(ifacename)
	startTime := time.Now()
	for d != nil && d.Name == ifacename {
		if err = RemoveConf(ifacename, false); err != nil { // remove interface first
			if strings.Contains(err.Error(), "does not exist") {
				err = nil
				break
			}
		}
		time.Sleep(time.Second >> 2)
		d, _ = wgclient.Device(ifacename)
		if time.Now().After(startTime.Add(time.Second << 4)) {
			break
		}
	}
	time.Sleep(time.Second << 1)
}

// RemoveConf - removes a configuration for a given WireGuard interface
func RemoveConf(iface string, printlog bool) error {
	os := runtime.GOOS
	if ncutils.IsLinux() && !ncutils.HasWgQuick() {
		os = "nowgquick"
	}
	var err error
	switch os {
	case "nowgquick":
		err = RemoveWithoutWGQuick(iface)
	case "windows":
		err = RemoveWindowsConf(iface, printlog)
	default:
		confPath := ncutils.GetNetclientPathSpecific() + iface + ".conf"
		err = RemoveWGQuickConf(confPath, printlog)
	}
	return err
}

// RemoveWGQuickConf - calls wg-quick down
func RemoveWGQuickConf(confPath string, printlog bool) error {
	_, err := ncutils.RunCmd(fmt.Sprintf("wg-quick down %s", confPath), printlog)
	return err
}
