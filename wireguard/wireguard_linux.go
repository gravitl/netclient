package wireguard

import (
	"fmt"
	"net"
	"os"

	"github.com/gravitl/netmaker/logger"
	"github.com/vishvananda/netlink"
)

// NCIface.Create - creates a linux WG interface based on a node's host config
func (nc *NCIface) Create() error {
	if isKernelWireGuardPresent() {
		newLink := nc.getKernelLink()
		if newLink == nil {
			return fmt.Errorf("failed to create kernel interface")
		}
		nc.Iface = newLink
		l, err := netlink.LinkByName(nc.Name)
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
		if err = netlink.LinkSetUp(newLink); err != nil {
			return err
		}
		return nil
	} else if isTunModuleLoaded() {
		if err := nc.createUserSpaceWG(); err != nil {
			return err
		}
	}
	return fmt.Errorf("WireGuard not detected")
}

// NCIface.SetMTU - sets the mtu for the interface
func (n *NCIface) SetMTU() error {
	l := n.getKernelLink()
	if err := netlink.LinkSetMTU(l, n.MTU); err != nil {
		return err
	}
	return nil
}

// netLink.Attrs - implements required function of NetLink package
func (l *netLink) Attrs() *netlink.LinkAttrs {
	return l.attrs
}

// netLink.Type - returns type of link i.e wireguard
func (l *netLink) Type() string {
	return "wireguard"
}

// NCIface.Close closes netmaker interface
func (n *NCIface) Close() {
	link := n.getKernelLink()
	link.Close()
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
	routes, err := netlink.RouteList(l, 0)
	if err != nil {
		return err
	}

	for i := range routes {
		err = netlink.RouteDel(&routes[i])
		if err != nil {
			return err
		}
	}

	if len(currentAddrs) > 0 {
		for i := range currentAddrs {
			err = netlink.AddrDel(l, &currentAddrs[i])
			if err != nil {
				return err
			}
		}
	}
	for _, addr := range nc.Addresses {
		if !addr.AddRoute && addr.IP != nil {
			logger.Log(3, "adding address", addr.IP.String(), "to netmaker interface")
			if err := netlink.AddrAdd(l, &netlink.Addr{IPNet: &net.IPNet{IP: addr.IP, Mask: addr.Network.Mask}}); err != nil {
				logger.Log(0, "error adding addr", err.Error())
				return err
			}
		}
		if addr.AddRoute {
			logger.Log(3, "adding route", addr.IP.String(), "to netmaker interface")
			if err := netlink.RouteAdd(&netlink.Route{
				LinkIndex: l.Attrs().Index,
				Dst:       &addr.Network,
			}); err != nil {
				logger.Log(0, "error adding addr", err.Error())
				return err
			}
		}

	}
	return nil
}

// == private ==

type netLink struct {
	attrs *netlink.LinkAttrs
}

func (nc *NCIface) getKernelLink() *netLink {
	link := getNewLink(nc.Name)
	return link
}

func getNewLink(name string) *netLink {
	linkAttrs := netlink.NewLinkAttrs()
	linkAttrs.Name = name
	return &netLink{
		attrs: &linkAttrs,
	}
}
