package wireguard

import (
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
	"github.com/vishvananda/netlink"
)

// Create - creates a linux WG interface based on a node's given config
func (nc *NCIface) Create() error {
	return ApplyConf(nc)
}

// Delete - removes wg network interface from machine
func (nc *NCIface) Delete() error {
	return RemoveWGQuickConf()
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
	if len(currentAddrs) > 0 {
		for i := range currentAddrs {
			err = netlink.AddrDel(l, &currentAddrs[i])
			if err != nil {
				return err
			}
		}
	}
	for _, node := range config.GetNodes() {
		var address netlink.Addr
		var address6 netlink.Addr
		address.IPNet = &node.Address
		if address.IPNet.IP != nil {
			logger.Log(3, "adding address ", address.IP.String(), "to netmaker address")
			if err := netlink.AddrAdd(l, &address); err != nil {
				logger.Log(0, "error adding addr", err.Error())
				return err
			}
		}
		address6.IPNet = &node.Address6
		if address6.IPNet.IP != nil {
			logger.Log(3, "adding address", address6.IP.String(), "to netmaker interface")
			err = netlink.AddrAdd(l, &address6)
			if err != nil {
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
	linkAttrs := netlink.NewLinkAttrs()
	linkAttrs.Name = getName()
	return &netLink{
		attrs: &linkAttrs,
	}
}
