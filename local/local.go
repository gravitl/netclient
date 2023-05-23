// Package local provide functions for setting routes
package local

import (
	"errors"
	"net"
	"os"
	"runtime"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
)

// SetIPForwarding - Sets IP forwarding if it's mac or linux
func SetIPForwarding() error {
	os := runtime.GOOS
	var err error
	switch os {
	case "linux":
		err = SetIPForwardingUnix()
	case "freebsd":
		err = SetIPForwardingFreeBSD()
	case "darwin":
		err = SetIPForwardingMac()
	case "windows":
		err = SetIPForwardingWindows()
	default:
		err = errors.New("this OS is not currently supported")
	}
	return err
}

// SetIPForwardingUnix - sets the ipforwarding for linux
func SetIPForwardingUnix() error {
	// ipv4
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), os.ModePerm); err != nil {
		logger.Log(0, "WARNING: Error encountered setting ip forwarding. This can break functionality.")
		return err
	}
	// ipv6
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), os.ModePerm); err != nil {

		logger.Log(0, "WARNING: Error encountered setting ip forwarding. This can break functionality.")
		return err
	}
	return nil
}

// SetIPForwardingFreeBSD - sets the ipforwarding for freebsd
func SetIPForwardingFreeBSD() error {
	if _, err := ncutils.RunCmd("sysctl -w net.inet.ip.forwarding=1", true); err != nil {
		logger.Log(0, "WARNING: Error encountered setting ip forwarding. You may want to investigate this.")
		return err
	}
	return nil
}

// SetIPForwardingMac - sets ip forwarding for mac
func SetIPForwardingMac() error {
	_, err := ncutils.RunCmd("sysctl -w net.inet.ip.forwarding=1", true)
	if err != nil {
		logger.Log(0, "WARNING: Error encountered setting ip forwarding. This can break functionality.")
	}
	return err
}

// SetIPForwardingWindows - sets ip forwarding for windows
func SetIPForwardingWindows() error {
	if _, err := ncutils.RunCmd("Set-NetIPInterface -Forwarding Enabled", true); err != nil {
		logger.Log(0, "WARNING: Error encountered setting ip forwarding. This can break functionality.")
		return err
	}
	return nil

}

// GetMacIface - gets mac interface
func GetMacIface(ipstring string) (string, error) {
	var wgiface string
	_, checknet, err := net.ParseCIDR(ipstring + "/24")
	if err != nil {
		return wgiface, errors.New("could not parse ip " + ipstring)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return wgiface, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := addr.(*net.IPNet).IP
			if checknet.Contains(ip) {
				wgiface = iface.Name
				break
			}
		}
	}
	if wgiface == "" {
		err = errors.New("could not find iface for address " + ipstring)
	}
	return wgiface, err
}
