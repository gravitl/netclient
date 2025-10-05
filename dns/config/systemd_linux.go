package config

import (
	"fmt"
	"os/exec"
	"strings"
)

type systemdManager struct{}

func newSystemdManager() (*systemdManager, error) {
	return &systemdManager{}, nil
}

func (s *systemdManager) Configure(config Config) error {
	if config.Interface == "" {
		return fmt.Errorf("interface is required")
	}

	if len(config.Nameservers) == 0 {
		err := s.resetConfig(config.Interface)
		if err != nil {
			return err
		}
	} else {
		dns := make([]string, len(config.Nameservers))
		for i, ip := range config.Nameservers {
			dns[i] = ip.String()
		}

		searchDomains := make([]string, len(config.SearchDomains))
		for i, domain := range config.SearchDomains {
			if domain == "." {
				searchDomains[i] = "~."
			} else {
				searchDomains[i] = domain
			}
		}

		err := exec.Command("resolvectl", "dns", config.Interface, strings.Join(dns, " ")).Run()
		if err != nil {
			return err
		}

		err = exec.Command("resolvectl", "domain", config.Interface, strings.Join(searchDomains, " ")).Run()
		if err != nil {
			return err
		}

		err = exec.Command("resolvectl", "default-route", config.Interface, "no").Run()
		if err != nil {
			return err
		}
	}

	return s.flushChanges()
}

func (s *systemdManager) resetConfig(ifaceName string) error {
	err := exec.Command("resolvectl", "dns", ifaceName, "").Run()
	if err != nil {
		return err
	}

	return exec.Command("resolvectl", "domain", ifaceName, "").Run()
}

func (s *systemdManager) flushChanges() error {
	return exec.Command("systemctl", "restart", "systemd-resolved.service").Run()
}

func (s *systemdManager) SupportsInterfaceSpecificConfig() bool {
	return true
}
