package config

import (
	"bytes"
	"fmt"
	"os/exec"
)

type openresolvManager struct{}

func newOpenresolvManager() (*openresolvManager, error) {
	return &openresolvManager{}, nil
}

func (o *openresolvManager) Configure(config Config) error {
	if config.Interface == "" {
		return fmt.Errorf("interface is required")
	}

	if len(config.Nameservers) == 0 {
		return o.resetConfig(config.Interface)
	}

	confBytes := new(bytes.Buffer)

	writeConfig(confBytes, config.Nameservers, config.SearchDomains)

	cmd := exec.Command("resolvconf", "-m", "0", "-x", "-a", config.Interface)
	cmd.Stdin = confBytes
	return cmd.Run()
}

func (o *openresolvManager) resetConfig(ifaceName string) error {
	return exec.Command("resolvconf", "-f", "-d", ifaceName).Run()
}

func (o *openresolvManager) SupportsInterfaceSpecificConfig() bool {
	return true
}
