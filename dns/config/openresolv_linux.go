package config

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
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
	out, err := exec.Command("resolvconf", "-d", iface).CombinedOutput()
	if err != nil {
		out := strings.TrimSpace(string(out))
		if strings.Contains(out, "No resolv.conf for interface") ||
			strings.Contains(out, "Failed to resolve interface") ||
			strings.Contains(out, "No such device") {
			return nil
		}

		return err
	}

	return nil
}
