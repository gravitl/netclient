package router

import (
	"errors"
	"net"
	"os/exec"

	"github.com/coreos/go-iptables/iptables"
	"github.com/gravitl/netmaker/logger"
	"github.com/vishvananda/netlink"
)

// newFirewall if supported, returns an ipfw manager
func newFirewall() (firewallController, error) {
	if isIpfwSupported() {
		logger.Log(0, "ipfw is supported")
		return &ipfwManager{}, nil
	}
	return nil, errors.New("firewall support not found")
}

func isIpfwSupported() bool {
	_, err := exec.LookPath("ipfw")
	return err == nil
}
