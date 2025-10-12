package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	netmakerResolverFileMarker = "# Managed by netmaker\n"
)

type darwinManager struct {
	config map[string]Config
}

func NewManager(opts ...ManagerOption) (Manager, error) {
	d := &darwinManager{
		config: make(map[string]Config),
	}
	var options ManagerOptions
	for _, opt := range opts {
		opt(&options)
	}

	if options.cleanupResidual {
		for _, iface := range options.residualInterfaces {
			err := d.resetConfig(iface)
			if err != nil {
				// TODO: suppress iface does not exist
				return nil, fmt.Errorf("failed to cleanup config for interface (%s): %v", iface, err)
			}
		}
	}

	return d, nil
}

func (d *darwinManager) Configure(iface string, config Config) error {
	if iface == "" {
		return fmt.Errorf("interface name is required")
	}

	if config.Remove {
		err := d.resetConfig(iface)
		if err != nil {
			return err
		}
	}

	d.config[iface] = config

	err := d.setMatchDomains()
	if err != nil {
		return err
	}

	return d.setSearchDomains(iface)
}

func (d *darwinManager) setMatchDomains() error {
	matchDomains := make(map[string][]net.IP)
	for _, config := range d.config {
		for _, searchDomain := range config.SearchDomains {
			matchDomains[searchDomain] = append(matchDomains[searchDomain], config.Nameservers...)
		}
	}

	for domain, nameservers := range matchDomains {
		resolverConf := new(bytes.Buffer)
		resolverFilePath := filepath.Join("/etc/resolver", domain)

		resolverConf.WriteString(netmakerResolverFileMarker)
		for _, nameserver := range nameservers {
			resolverConf.WriteString(fmt.Sprintf("nameserver %s\n", nameserver.String()))
		}

		err := os.WriteFile(resolverFilePath, resolverConf.Bytes(), 0644)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *darwinManager) setSearchDomains(iface string) error {
	config := d.config[iface]

	err := exec.Command("networksetup", "-createnetworkservice", fmt.Sprintf("Netmaker-%s", iface), iface).Run()
	if err != nil {
		return err
	}

	var dnsServers []string
	for _, nameserver := range config.Nameservers {
		dnsServers = append(dnsServers, nameserver.String())
	}

	args := []string{"-setdnsservers", fmt.Sprintf("Netmaker-%s", iface)}
	args = append(args, dnsServers...)
	err = exec.Command("networksetup", args...).Run()
	if err != nil {
		return err
	}

	args = []string{"-setsearchdomains", fmt.Sprintf("Netmaker-%s", iface)}
	args = append(args, config.SearchDomains...)
	err = exec.Command("networksetup", args...).Run()
	if err != nil {
		return err
	}

	out, err := exec.Command("networksetup", "-listnetworkserviceorder").Output()
	if err != nil {
		return err
	}

	lines := strings.Split(string(out), "\n")
	serviceRegex := regexp.MustCompile(`^\(\*?\d*\)\s+(.+?)\s+\(Hardware Port:`)

	var services []string
	for _, line := range lines {
		match := serviceRegex.FindStringSubmatch(line)
		if len(match) > 1 {
			service := strings.TrimSpace(match[1])
			if !strings.HasPrefix(service, "Netmaker-") {
				services = append(services, service)
			}
		}
	}

	var highPriority []string
	var mediumPriority []string
	for iface, config := range d.config {
		if config.SplitDNS {
			mediumPriority = append(mediumPriority, fmt.Sprintf("Netmaker-%s", iface))
		} else {
			highPriority = append(highPriority, fmt.Sprintf("Netmaker-%s", iface))
		}
	}

	var order []string
	order = append(order, highPriority...)
	order = append(order, mediumPriority...)
	order = append(order, services...)
	order = append(order, services...)

	args = []string{"-ordernetworkservices"}
	args = append(args, order...)
	return exec.Command("networksetup", args...).Run()
}

func (d *darwinManager) resetConfig(iface string) error {
	err := d.resetSearchDomains(iface)
	if err != nil {
		return err
	}

	err = d.resetMatchDomains()
	if err != nil {
		return err
	}

	delete(d.config, iface)

	return d.setMatchDomains()
}

func (d *darwinManager) resetMatchDomains() error {
	resolverFiles, err := os.ReadDir("/etc/resolver")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, resolverFile := range resolverFiles {
		if !resolverFile.Type().IsRegular() {
			continue
		}

		resolverFilePath := filepath.Join("/etc/resolver", resolverFile.Name())
		contents, err := os.ReadFile(resolverFilePath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}

		if !strings.HasPrefix(string(contents), netmakerResolverFileMarker) {
			continue
		}

		err = os.Remove(resolverFilePath)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *darwinManager) resetSearchDomains(iface string) error {
	return exec.Command("networksetup", "-removenetworkservice", fmt.Sprintf("Netmaker-%s", iface)).Run()
}
