package config

import (
	"bytes"
	"fmt"
	"os/exec"
)

type openresolvManager struct{}

func newOpenresolvManager(opts ...ManagerOption) (*openresolvManager, error) {
	o := &openresolvManager{}
	var options ManagerOptions
	for _, opt := range opts {
		opt(&options)
	}

	if options.cleanupResidual {
		for _, iface := range options.residualInterfaces {
			err := o.resetConfig(iface)
			if err != nil {
				// TODO: suppress iface does not exist
				return nil, fmt.Errorf("failed to cleanup config for interface (%s): %v", iface, err)
			}
		}
	}

	return o, nil
}

func (o *openresolvManager) Configure(iface string, config Config) error {
	if iface == "" {
		return fmt.Errorf("interface name is required")
	}

	if config.Remove {
		return o.resetConfig(iface)
	}

	confBytes := new(bytes.Buffer)

	writeConfig(confBytes, config.Nameservers, config.SearchDomains)

	cmd := exec.Command("resolvconf", "-m", "0", "-x", "-a", iface)
	cmd.Stdin = confBytes
	return cmd.Run()
}

func (o *openresolvManager) resetConfig(iface string) error {
	return exec.Command("resolvconf", "-d", iface).Run()
}
