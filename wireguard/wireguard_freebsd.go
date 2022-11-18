package wireguard

import (
	"fmt"
	"os"

	"github.com/gravitl/netclient/local"
	"github.com/vishvananda/netlink"
)

// Create - creates a linux WG interface based on a node's given config
func (nc *NCIface) Create() error {

	if local.IsKernelWGInstalled() { // TODO detect if should use userspace or kernel
		newLink := nc.getKernelLink()
		if newLink == nil {
			return fmt.Errorf("failed to create kernel interface")
		}
		l, err := netlink.LinkByName(nc.Settings.Interface)
		if err != nil {
			switch err.(type) {
			case netlink.LinkNotFoundError:
				break
			default:
				return err
			}
		}
		if l != nil {
			err = netlink.LinkDel(newLink)
			if err != nil {
				return err
			}
		}
		if err = netlink.LinkAdd(newLink); err != nil && !os.IsExist(err) {
			return err
		}

		if err = nc.ApplyAddrs(); err != nil {
			return err
		}

		if err = netlink.LinkSetMTU(newLink, nc.Settings.MTU); err != nil {
			return err
		}

		if err = netlink.LinkSetUp(newLink); err != nil {
			return err
		}
		return nil
	} else if local.IsUserSpaceWGInstalled() {
		if err := nc.createUserSpaceWG(); err != nil {
			return err
		}
	}
	return fmt.Errorf("WireGuard not detected")
}

// Delete - removes wg network interface from machine
func (nc *NCIface) Delete() error {
	l := nc.getKernelLink()
	if l == nil {
		return fmt.Errorf("no associated link found")
	}

	return netlink.LinkDel(l)
}

// netLink.Attrs - implements required function of NetLink package
func (l *netLink) Attrs() *netlink.LinkAttrs {
	return l.attrs
}

// netLink.Type - returns type of link i.e wireguard
func (l *netLink) Type() string {
	return "wireguard"
}

// netLink.Close - required function to close linux interface
func (l *netLink) Close() error {
	return netlink.LinkDel(l)
}

// netLink.ApplyAddrs - applies the assigned node addresses to given interface (netLink)
func (nc *NCIface) ApplyAddrs() error {
	l := nc.getKernelLink()

	currentAddrs, err := netlink.AddrList(l, 0)
	if err != nil {
		return err
	}

	if len(currentAddrs) > 0 {
		for i := range currentAddrs {
			err = netlink.AddrDel(l, &currentAddrs[i])
			if err != nil {
				return err
			}
		}
	}

	addr, err := netlink.ParseAddr(nc.Settings.Address.String())
	if err == nil {
		err = netlink.AddrAdd(l, addr)
		if err != nil {
			return err
		}
	}
	addr6, err := netlink.ParseAddr(nc.Settings.Address6.String())
	if err == nil {
		err = netlink.AddrAdd(l, addr6)
		if err != nil {
			return err
		}
	}
	return nil
}

// == private ==

type netLink struct {
	attrs *netlink.LinkAttrs
}

func (nc *NCIface) getKernelLink() *netLink {
	linkAttrs := netlink.NewLinkAttrs()
	linkAttrs.Name = nc.Settings.Interface
	return &netLink{
		attrs: &linkAttrs,
	}
}
