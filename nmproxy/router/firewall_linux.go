package router

import (
	"errors"
	"net"
	"os/exec"

	"github.com/coreos/go-iptables/iptables"
	"github.com/gravitl/netmaker/logger"
	"github.com/vishvananda/netlink"
)

// newFirewall if supported, returns an iptables manager, otherwise returns a nftables manager
func newFirewall() (firewallController, error) {

	var manager firewallController
	if isIptablesSupported() {
		logger.Log(0, "iptables is supported")
		ipv4Client, _ := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		ipv6Client, _ := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		manager = &iptablesManager{
			ipv4Client:   ipv4Client,
			ipv6Client:   ipv6Client,
			ingRules:     make(serverrulestable),
			engressRules: make(serverrulestable),
		}
		return manager, nil
	}

	//logger.Log(0, "iptables is not supported, using nftables")

	// TODO - nft table manager

	return manager, errors.New("firewall support not found")
}

func isIptablesSupported() bool {
	_, err4 := exec.LookPath("iptables")
	_, err6 := exec.LookPath("ip6tables")
	return err4 == nil && err6 == nil
}

func getInterfaceName(dst net.IPNet) (string, error) {
	h, err := netlink.NewHandle(0)
	if err != nil {
		return "", err
	}
	routes, err := h.RouteGet(dst.IP)
	if err != nil {
		return "", err
	}
	for _, r := range routes {
		iface, err := net.InterfaceByIndex(r.LinkIndex)
		if err == nil {
			return iface.Name, nil
		}
	}
	return "", errors.New("interface not found for: " + dst.String())
}
