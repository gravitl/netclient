// Package local provide functions for setting routes
package local

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"

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
	default:
		err = errors.New("this OS is not currently supported")
	}
	return err
}

// SetIPForwardingUnix - sets the ipforwarding for linux
func SetIPForwardingUnix() error {
	// ipv4
	out, err := ncutils.RunCmd("sysctl net.ipv4.ip_forward", true)
	if err != nil {
		logger.Log(0, "WARNING: Error encountered setting ip forwarding. This can break functionality.")
		return err
	} else {
		s := strings.Fields(string(out))
		if s[2] != "1" {
			_, err = ncutils.RunCmd("sysctl -w net.ipv4.ip_forward=1", true)
			if err != nil {
				logger.Log(0, "WARNING: Error encountered setting ip forwarding. You may want to investigate this.")
				return err
			}
		}
	}
	// ipv6
	out, err = ncutils.RunCmd("sysctl net.ipv6.conf.all.forwarding", true)
	if err != nil {
		logger.Log(0, "WARNING: Error encountered setting ipv6 forwarding. This can break functionality.")
		return err
	} else {
		s := strings.Fields(string(out))
		if s[2] != "1" {
			_, err = ncutils.RunCmd("sysctl -w  net.ipv6.conf.all.forwarding=1", true)
			if err != nil {
				logger.Log(0, "WARNING: Error encountered setting ipv6 forwarding. You may want to investigate this.")
				return err
			}
		}
	}
	return nil
}

// SetIPForwardingFreeBSD - sets the ipforwarding for freebsd
func SetIPForwardingFreeBSD() error {
	out, err := ncutils.RunCmd("sysctl net.inet.ip.forwarding", true)
	if err != nil {
		logger.Log(0, "WARNING: Error encountered setting ip forwarding. This can break functionality.")
		return err
	} else {
		s := strings.Fields(string(out))
		if s[1] != "1" {
			_, err = ncutils.RunCmd("sysctl -w net.inet.ip.forwarding=1", true)
			if err != nil {
				logger.Log(0, "WARNING: Error encountered setting ip forwarding. You may want to investigate this.")
				return err
			}
		}
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

// IsKernelWGInstalled - checks if WireGuard is installed
func IsKernelWGInstalled() bool {
	out, err := ncutils.RunCmd("wg help", true)
	if err != nil {
		return false
	}
	return strings.Contains(out, "Available subcommand") && !IsUserSpaceWGInstalled()
}

// IsUserSpaceWGInstalled - checks if userspace WG is present
func IsUserSpaceWGInstalled() bool {
	_, err := exec.LookPath(os.Getenv("WG_QUICK_USERSPACE_IMPLEMENTATION"))
	return err == nil
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
