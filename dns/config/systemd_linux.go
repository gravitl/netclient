package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/ini.v1"
)

const (
	systemdOverrideConfDir  = "/run/systemd/resolved.conf.d"
	systemdOverrideConfFile = "netmaker.conf"
)

type systemdManager struct{}

func newSystemdManager() (*systemdManager, error) {
	err := os.MkdirAll(systemdOverrideConfDir, 0755)
	if err != nil {
		return nil, err
	}

	return &systemdManager{}, nil
}

func (s *systemdManager) Configure(config Config) error {
	if len(config.Nameservers) == 0 {
		err := s.resetConfig()
		if err != nil {
			return err
		}
	} else {
		systemdConfigPath := filepath.Join(systemdOverrideConfDir, systemdOverrideConfFile)
		systemdConfig := ini.Empty()

		resolveSection, err := systemdConfig.NewSection("Resolve")
		if err != nil {
			return err
		}

		dns := make([]string, len(config.Nameservers))

		for i, ip := range config.Nameservers {
			dns[i] = ip.String()
		}

		_, err = resolveSection.NewKey("DNS", strings.Join(dns, " "))
		if err != nil {
			return err
		}

		searchDomains := make([]string, len(config.SearchDomains))

		for i, domain := range config.SearchDomains {
			if domain == "." {
				searchDomains[i] = "~."
			}
		}

		_, err = resolveSection.NewKey("Domains", strings.Join(searchDomains, " "))
		if err != nil {
			return err
		}

		configFile, err := os.Create(systemdConfigPath)
		if err != nil {
			return err
		}

		_, err = systemdConfig.WriteTo(configFile)
		if err != nil {
			return err
		}
	}

	return s.flushChanges()
}

func (s *systemdManager) resetConfig() error {
	return os.Remove(filepath.Join(systemdOverrideConfDir, systemdOverrideConfFile))
}

func (s *systemdManager) flushChanges() error {
	return exec.Command("systemctl", "restart", "systemd-resolved.service").Run()
}

func (s *systemdManager) SupportsInterfaceSpecificConfig() bool {
	return false
}
