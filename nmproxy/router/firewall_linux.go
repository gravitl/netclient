package router

import (
	"os/exec"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/nftables"
	"github.com/gravitl/netmaker/logger"
)

// newFirewall if supported, returns an iptables manager, otherwise returns a nftables manager
func newFirewall() firewallController {

	var manager firewallController
	if isIptablesSupported() {
		logger.Log(0, "iptables is supported")
		ipv4Client, _ := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		ipv6Client, _ := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		manager = &iptablesManager{
			ipv4Client: ipv4Client,
			ipv6Client: ipv6Client,
			ingRules:   make(serverrulestable),
		}
		return manager
	}

	logger.Log(0, "iptables is not supported, using nftables")

	if isNftablesSupported() {
		logger.Log(0, "nftables is supported")
		manager = &nftablesManager{
			conn:     &nftables.Conn{},
			ingRules: make(serverrulestable),
		}
		return manager
	}

	logger.Log(0, "failed to initialize firewall, either iptables or nftables is required")
	return manager
}

func isIptablesSupported() bool {
	_, err4 := exec.LookPath("iptables")
	_, err6 := exec.LookPath("ip6tables")
	return err4 == nil && err6 == nil
}

func isNftablesSupported() bool {
	_, err := exec.LookPath("nft")
	return err == nil
}
