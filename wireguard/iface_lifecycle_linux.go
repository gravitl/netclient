//go:build linux

package wireguard

import (
	"fmt"

	"github.com/gravitl/netclient/ncutils"
	"github.com/vishvananda/netlink"
)

func listHostWireGuardInterfaces() []ReconcileEntry {
	links, err := netlink.LinkList()
	if err != nil {
		return nil
	}
	desired := ncutils.GetInterfaceName()
	entries := make([]ReconcileEntry, 0)
	for _, link := range links {
		if link.Type() != "wireguard" {
			continue
		}
		attrs := link.Attrs()
		if attrs == nil {
			continue
		}
		entries = append(entries, ReconcileEntry{
			Name:        attrs.Name,
			Type:        link.Type(),
			Owned:       isNetclientOwnedLink(attrs, desired),
			Present:     true,
			IsWireGuard: true,
			Alias:       attrs.Alias,
		})
	}
	return entries
}

func isNetclientOwnedLink(attrs *netlink.LinkAttrs, desired string) bool {
	if attrs == nil {
		return false
	}
	if attrs.Alias == NetclientIfaceAlias {
		return true
	}
	return attrs.Name == desired
}

func isWireGuardLink(link netlink.Link) bool {
	return link != nil && link.Type() == "wireguard"
}

func markNetclientOwnership(link netlink.Link) error {
	attrs := link.Attrs()
	if attrs == nil {
		return fmt.Errorf("link has no attributes")
	}
	if attrs.Alias == NetclientIfaceAlias {
		return nil
	}
	return netlink.LinkSetAlias(link, NetclientIfaceAlias)
}

func deleteLinkByName(name, reason, caller string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil
		}
		IfaceMetrics.CreateErrorsTotal.Add(1)
		logIfaceOp("delete", name, reason, caller, err)
		return err
	}
	if !isNetclientOwnedLink(link.Attrs(), ncutils.GetInterfaceName()) {
		logIfaceOp("delete_skipped", name, reason, caller, fmt.Errorf("not netclient-owned"))
		return nil
	}
	if err := netlink.LinkDel(link); err != nil {
		IfaceMetrics.CreateErrorsTotal.Add(1)
		logIfaceOp("delete", name, reason, caller, err)
		return err
	}
	IfaceMetrics.DeleteTotal.Add(1)
	clearCreateRate(name)
	logIfaceOp("delete", name, reason, caller, nil)
	return nil
}

func cachedKernelWireGuardPresent() bool {
	kernelWGPresentMu.Lock()
	defer kernelWGPresentMu.Unlock()
	if kernelWGPresent != nil {
		return *kernelWGPresent
	}
	present := isKernelWireGuardPresent()
	kernelWGPresent = &present
	return present
}
