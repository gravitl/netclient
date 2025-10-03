package config

import (
	"bytes"
	"fmt"
	"os/exec"
)

type resolvconfManager struct{}

func newResolvconfManager() (*resolvconfManager, error) {
	return &resolvconfManager{}, nil
}

func (r *resolvconfManager) Configure(config Config) error {
	if config.Interface == "" {
		return fmt.Errorf("interface is required")
	}

	if len(config.Nameservers) == 0 {
		return r.resetConfig(config.Interface)
	}

	confBytes := new(bytes.Buffer)

	writeConfig(confBytes, config.Nameservers, config.SearchDomains)

	cmd := exec.Command("resolvconf", "-a", config.Interface)
	cmd.Stdin = confBytes
	return cmd.Run()
}

func (r *resolvconfManager) resetConfig(ifaceName string) error {
	return exec.Command("resolvconf", "-d", ifaceName).Run()
}

func (r *resolvconfManager) SupportsInterfaceSpecificConfig() bool {
	return true
}
