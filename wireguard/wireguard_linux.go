package wireguard

import (
	"fmt"
	"log"
	"os"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/local"
	"github.com/kr/pretty"
	"github.com/vishvananda/netlink"
)

// NCIface.Create - creates a linux WG interface based on a node's host config
func (nc *NCIface) Create() error {

	if local.IsKernelWGInstalled() { // TODO detect if should use userspace or kernel
		newLink := nc.getKernelLink()
		if newLink == nil {
			return fmt.Errorf("failed to create kernel interface")
		}
		nc.Iface = newLink
		l, err := netlink.LinkByName(getName())
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

		if err = netlink.LinkSetMTU(newLink, nc.Host.MTU); err != nil {
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
	for _, node := range config.Nodes {
		log.Println("adding address from node ", node.ID)

		addr, err := netlink.ParseAddr(node.Address.String())
		pretty.Println(addr, err)
		if err == nil {
			err = netlink.AddrAdd(l, addr)
			if err != nil {
				return err
			}
		}
		addr6, err := netlink.ParseAddr(node.Address6.String())
		pretty.Println(addr6, err)
		if err == nil {
			err = netlink.AddrAdd(l, addr6)
			if err != nil {
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
	link := getNewLink(getName())
	return link
}

func getNewLink(name string) *netLink {
	linkAttrs := netlink.NewLinkAttrs()
	linkAttrs.Name = name
	return &netLink{
		attrs: &linkAttrs,
	}
}
