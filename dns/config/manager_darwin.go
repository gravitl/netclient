package config

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

const (
	netmakerResolverFileMarker = "# Managed by netmaker\n"
)

type darwinManager struct {
	config map[string]Config
	mu     sync.Mutex
}

type nameserver struct {
	ips            []string
	isSearchDomain bool
}

func NewManager(opts ...ManagerOption) (Manager, error) {
	d := &darwinManager{
		config: make(map[string]Config),
	}
	var options ManagerOptions
	for _, opt := range opts {
		opt(&options)
	}

	err := os.MkdirAll("/etc/resolver", 0755)
	if err != nil {
		return nil, err
	}

	if options.cleanupResidual && len(options.residualInterfaces) > 0 {
		err = d.resetConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to cleanup config: %v", err)
		}
	}

	return d, nil
}

func (d *darwinManager) Configure(iface string, config Config) error {
	if iface == "" {
		return fmt.Errorf("interface name is required")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if config.Remove {
		delete(d.config, iface)
	} else {
		d.config[iface] = config
	}

	domainNameservers := make(map[string]*nameserver)
	globalNameserversMap := make(map[string]bool)
	searchDomainsMap := make(map[string]bool)

	var globalNameservers, globalSearchDomains []string

	for _, config := range d.config {
		if config.SplitDNS {
			nameservers := make([]string, len(config.Nameservers))
			for i, ns := range config.Nameservers {
				nameservers[i] = ns.String()
			}

			for _, matchDomain := range config.MatchDomains {
				_, ok := domainNameservers[matchDomain]
				if !ok {
					domainNameservers[matchDomain] = &nameserver{}
				}

				domainNameservers[matchDomain].ips = append(domainNameservers[matchDomain].ips, nameservers...)
			}
		} else {
			for _, ns := range config.Nameservers {
				globalNameserversMap[ns.String()] = true
			}
		}

		for _, searchDomain := range config.SearchDomains {
			searchDomainsMap[searchDomain] = true
		}
	}

	for ns := range globalNameserversMap {
		globalNameservers = append(globalNameservers, ns)
	}

	for domain := range searchDomainsMap {
		if len(globalNameservers) > 0 {
			globalSearchDomains = append(globalSearchDomains, domain)
		}

		_, ok := domainNameservers[domain]
		if ok {
			domainNameservers[domain].isSearchDomain = true
		}
	}

	err := d.setupSplitDNS(domainNameservers)
	if err != nil {
		return err
	}

	return d.setupFullDNS(globalNameservers, globalSearchDomains)
}

func (d *darwinManager) setupSplitDNS(matchDomains map[string]*nameserver) error {
	err := d.resetSplitDNS()
	if err != nil {
		return err
	}

	for domain, nameserver := range matchDomains {
		resolverConf := new(bytes.Buffer)
		resolverFilePath := filepath.Join("/etc/resolver", domain)

		resolverConf.WriteString(netmakerResolverFileMarker)
		for _, ip := range nameserver.ips {
			resolverConf.WriteString(fmt.Sprintf("nameserver %s\n", ip))
		}

		if nameserver.isSearchDomain {
			resolverConf.WriteString(fmt.Sprintf("search %s\n", domain))
		}

		err := os.WriteFile(resolverFilePath, resolverConf.Bytes(), 0644)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *darwinManager) setupFullDNS(nameservers, searchDomains []string) error {
	services, err := d.listNetworkServices()
	if err != nil {
		return err
	}

	for _, service := range services {
		cerr := d.setServiceDNS(service, nameservers, searchDomains)
		if cerr != nil {
			err = cerr
		}
	}

	return err
}

func (d *darwinManager) resetConfig() error {
	err := d.resetSplitDNS()
	if err != nil {
		return err
	}

	return d.resetFullDNS()
}

func (d *darwinManager) resetSplitDNS() error {
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

func (d *darwinManager) resetFullDNS() error {
	services, err := d.listNetworkServices()
	if err != nil {
		return err
	}

	for _, service := range services {
		cerr := d.setServiceDNS(service, nil, nil)
		if cerr != nil {
			err = cerr
		}
	}

	return err
}

func (d *darwinManager) listNetworkServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").CombinedOutput()
	if err != nil {
		return nil, err
	}

	var services []string
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "An asterisk (*) denotes that a network service is disabled.") {
			continue
		}

		line = strings.TrimPrefix(line, "*")
		services = append(services, line)
	}

	return services, nil
}

func (d *darwinManager) setServiceDNS(service string, nameservers, searchDomains []string) error {
	args := []string{
		"-setdnsservers",
		service,
	}

	if len(nameservers) > 0 {
		args = append(args, nameservers...)
	} else {
		args = append(args, "Empty")
	}

	err := exec.Command("networksetup", args...).Run()
	if err != nil {
		return err
	}

	args = []string{
		"-setsearchdomains",
		service,
	}

	if len(searchDomains) > 0 {
		args = append(args, searchDomains...)
	} else {
		args = append(args, "Empty")
	}

	return exec.Command("networksetup", args...).Run()
}
