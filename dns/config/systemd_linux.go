package config

import (
	"fmt"
	"os/exec"
	"strings"
)

type systemdManager struct{}

func newSystemdManager(opts ...ManagerOption) (*systemdManager, error) {
	s := &systemdManager{}
	var options ManagerOptions
	for _, opt := range opts {
		opt(&options)
	}

	if options.cleanupResidual {
		for _, iface := range options.residualInterfaces {
			err := s.resetConfig(iface)
			if err != nil {
				return nil, fmt.Errorf("failed to cleanup config for interface (%s): %v", iface, err)
			}
		}
	}

	return s, nil
}

func (s *systemdManager) Configure(iface string, config Config) error {
	if iface == "" {
		return fmt.Errorf("interface name is required")
	}

	if config.Remove {
		err := s.resetConfig(iface)
		if err != nil {
			return err
		}
	} else {
		nameservers := make([]string, len(config.Nameservers))
		for i, ip := range config.Nameservers {
			nameservers[i] = ip.String()
		}

		domainsMap := make(map[string]bool)
		for _, domain := range config.MatchDomains {
			domainsMap[domain] = true
		}

		for _, domain := range config.SearchDomains {
			_, ok := domainsMap[domain]
			if ok {
				delete(domainsMap, domain)
			}

			domainsMap["~"+domain] = true
		}

		i := 0
		domains := make([]string, len(domainsMap))
		for domain := range domainsMap {
			domains[i] = domain
			i++
		}

		if !config.SplitDNS {
			domains = append(domains, "~.")
		}

		args := []string{"dns", iface}
		args = append(args, nameservers...)
		err := exec.Command("resolvectl", args...).Run()
		if err != nil {
			return err
		}

		args = []string{"domain", iface}
		args = append(args, domains...)
		err = exec.Command("resolvectl", args...).Run()
		if err != nil {
			return err
		}

		defaultRoute := "yes"
		if config.SplitDNS {
			defaultRoute = "no"
		}

		err = exec.Command("resolvectl", "default-route", iface, defaultRoute).Run()
		if err != nil {
			return err
		}
	}

	return s.flushChanges()
}

func (s *systemdManager) resetConfig(iface string) error {
	out, err := exec.Command("resolvectl", "dns", iface, "").CombinedOutput()
	if err != nil {
		out := strings.TrimSpace(string(out))
		if out == fmt.Sprintf("Failed to resolve interface \"%s\": No such device", iface) {
			return nil
		}

		return err
	}

	out, err = exec.Command("resolvectl", "domain", iface, "").CombinedOutput()
	if err != nil {
		out := strings.TrimSpace(string(out))
		if out == fmt.Sprintf("Failed to resolve domain \"%s\": No such device", iface) {
			return nil
		}

		return err
	}

	return nil
}

func (s *systemdManager) flushChanges() error {
	return exec.Command("systemctl", "restart", "systemd-resolved.service").Run()
}
