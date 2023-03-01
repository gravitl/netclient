package router

import (
	"errors"
	"os/exec"

	"github.com/gravitl/netmaker/logger"
)

// newFirewall if supported, returns an ipfw manager
func newFirewall() (firewallController, error) {
	if isIpfwSupported() {
		logger.Log(0, "ipfw is supported")
		return &ipfwManager{
			ingRules:     make(serverrulestable),
			engressRules: make(serverrulestable),
		}, nil
	}
	return nil, errors.New("firewall support not found")
}

func isIpfwSupported() bool {
	_, err := exec.LookPath("ipfw")
	return err == nil
}
