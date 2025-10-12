package config

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	nrptRuleMarker = "Managed by netmaker"
)

type windowsManager struct{}

func NewManager(opts ...ManagerOption) (Manager, error) {
	w := &windowsManager{}
	var options ManagerOptions
	for _, opt := range opts {
		opt(&options)
	}

	if options.cleanupResidual {
		err := w.resetConfig()
		if err != nil {
			return nil, err
		}
	}

	return w, nil
}

func (w *windowsManager) Configure(iface string, config Config) error {
	if iface == "" {
		return fmt.Errorf("interface name is required")
	}

	if config.Remove {
		return w.resetConfig()
	}

	var domains []string
	for _, domain := range config.SearchDomains {
		if domain != "." {
			domains = append(domains, domain)
		}
	}

	// write nrpt rules for routing queries.
	err := w.setNrptRules(config.Nameservers, config.SearchDomains)
	if err != nil {
		return err
	}

	// write registry config for dns query expansion.
	return w.setRegistry(config.Nameservers, domains)
}

func (w *windowsManager) setNrptRules(nameservers []net.IP, searchDomains []string) error {
	var nameserver string
	for _, ns := range nameservers {
		if nameserver == "" {
			nameserver = fmt.Sprintf("\"%s\"", ns.String())
		} else {
			nameserver = fmt.Sprintf("%s,\"%s\"", nameserver, ns.String())
		}
	}

	for _, domain := range searchDomains {
		if !strings.HasPrefix(domain, ".") {
			domain = "." + domain
		}

		addCmd := fmt.Sprintf("Add-DnsClientNrptRule -Namespace \"%s\" -NameServers %s -Comment \"%s\"", domain, nameserver, nrptRuleMarker)
		cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", addCmd)
		err := cmd.Run()
		if err != nil {
			return err
		}
	}

	return nil
}

func (w *windowsManager) setRegistry(nameservers []net.IP, searchDomains []string) error {
	skipIpv4 := true
	skipIpv6 := true
	for _, ns := range nameservers {
		if ns.To4() == nil {
			skipIpv4 = false
		} else {
			skipIpv6 = false
		}
	}

	if !skipIpv4 {
		err := w.setRegistrySearchList(searchDomains, false)
		if err != nil {
			return err
		}
	}

	if !skipIpv6 {
		err := w.setRegistrySearchList(searchDomains, true)
		if err != nil {
			return err
		}
	}

	return nil
}

func (w *windowsManager) setRegistrySearchList(searchDomains []string, ipv6 bool) error {
	searchListKey, err := w.getSearchListRegistryKey(ipv6)
	if err != nil {
		return err
	}
	defer func() {
		_ = searchListKey.Close()
	}()

	searchList, _, err := searchListKey.GetStringsValue("SearchList")
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			err = searchListKey.SetStringsValue("SearchList", searchDomains)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	} else {
		_, _, err = searchListKey.GetStringsValue("PreNetmakerSearchList")
		if err != nil {
			if errors.Is(err, registry.ErrNotExist) {
				err = searchListKey.SetStringsValue("PreNetmakerSearchList", searchDomains)
				if err != nil {
					return err
				}
			} else {
				return err
			}
		}

		searchList = append(searchDomains, searchList...)
		err = searchListKey.SetStringsValue("SearchList", searchList)
		if err != nil {
			return err
		}
	}

	return nil
}

func (w *windowsManager) resetConfig() error {
	err := w.resetNrptRules()
	if err != nil {
		return err
	}

	return w.resetRegistry()
}

func (w *windowsManager) resetNrptRules() error {
	getCmd := fmt.Sprintf("Get-DnsClientNrptRule | Where-Object {$_.Comment -eq \"%s\"} | Select-Object -ExpandProperty Name", nrptRuleMarker)
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", getCmd)
	output, err := cmd.Output()
	if err == nil {
		var names []string
		for _, name := range strings.Split(strings.TrimSpace(string(output)), "\r\n") {
			name = strings.TrimSpace(name)
			if name != "" {
				names = append(names, name)
			}
		}

		for _, name := range names {
			removeCmd := fmt.Sprintf("Remove-DnsClientNrptRule -Name \"%s\" -Force", name)
			cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", removeCmd)
			err = cmd.Run()
			if err != nil {
				return err
			}
		}
	}

	return err
}

func (w *windowsManager) resetRegistry() error {
	var skipGlobal, skipIpv4, skipIpv6 bool
	globalSearchListKey, err := w.getGlobalSearchListRegistryKey()
	if err != nil {
		skipGlobal = true
	}

	ipv4SearchListKey, err := w.getIpv4SearchListRegistryKey()
	if err != nil {
		skipIpv4 = true
	}

	ipv6SearchListKey, err := w.getIpv6SearchListRegistryKey()
	if err != nil {
		skipIpv6 = true
	}

	defer func() {
		if !skipGlobal {
			_ = globalSearchListKey.Close()
		}

		if !skipIpv4 {
			_ = ipv4SearchListKey.Close()
		}

		if !skipIpv6 {
			_ = ipv6SearchListKey.Close()
		}
	}()

	if !skipGlobal {
		searchList, _, err := globalSearchListKey.GetStringsValue("PreNetmakerSearchList")
		if err != nil {
			if !errors.Is(err, registry.ErrNotExist) {
				return err
			}
		} else {
			err = globalSearchListKey.SetStringsValue("SearchList", searchList)
			if err != nil {
				return err
			}

			_ = globalSearchListKey.DeleteValue("PreNetmakerSearchList")
		}
	}

	if !skipIpv4 {
		searchList, _, err := ipv4SearchListKey.GetStringsValue("PreNetmakerSearchList")
		if err != nil {
			if !errors.Is(err, registry.ErrNotExist) {
				return err
			}
		} else {
			err = ipv4SearchListKey.SetStringsValue("SearchList", searchList)
			if err != nil {
				return err
			}

			_ = ipv4SearchListKey.DeleteValue("PreNetmakerSearchList")
		}
	}

	if !skipIpv6 {
		searchList, _, err := ipv6SearchListKey.GetStringsValue("PreNetmakerSearchList")
		if err != nil {
			if !errors.Is(err, registry.ErrNotExist) {
				return err
			}
		} else {
			err = ipv6SearchListKey.SetStringsValue("SearchList", searchList)
			if err != nil {
				return err
			}

			_ = ipv6SearchListKey.DeleteValue("PreNetmakerSearchList")
		}
	}

	return nil
}

func (w *windowsManager) getSearchListRegistryKey(ipv6 bool) (registry.Key, error) {
	key, err := w.getGlobalSearchListRegistryKey()
	if err != nil {
		if !errors.Is(err, registry.ErrNotExist) {
			return 0, err
		}
	} else {
		_, _, err = key.GetStringsValue("SearchList")
		if err != nil {
			_ = key.Close()
			if !errors.Is(err, registry.ErrNotExist) {
				return 0, err
			}
		} else {
			return key, nil
		}
	}

	if ipv6 {
		return w.getIpv6SearchListRegistryKey()
	}

	return w.getIpv4SearchListRegistryKey()
}

func (w *windowsManager) getGlobalSearchListRegistryKey() (registry.Key, error) {
	return registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, registry.ALL_ACCESS)
}

func (w *windowsManager) getIpv4SearchListRegistryKey() (registry.Key, error) {
	return registry.OpenKey(registry.LOCAL_MACHINE, `System\CurrentControlSet\Services\Tcpip\Parameters`, registry.ALL_ACCESS)
}

func (w *windowsManager) getIpv6SearchListRegistryKey() (registry.Key, error) {
	return registry.OpenKey(registry.LOCAL_MACHINE, `System\CurrentControlSet\Services\Tcpip6\Parameters`, registry.ALL_ACCESS)
}
