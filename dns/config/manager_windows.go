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

type windowsManager struct {
	configs map[string]Config
}

func NewManager(opts ...ManagerOption) (Manager, error) {
	w := &windowsManager{
		configs: make(map[string]Config),
	}
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
		delete(w.configs, iface)
	} else {
		w.configs[iface] = config
	}

	nameservers := make(map[string]bool)
	searchDomains := make(map[string]bool)
	var matchAllDomains bool
	for _, config := range w.configs {
		if !config.SplitDNS {
			matchAllDomains = true
		}

		for _, nameserver := range config.Nameservers {
			nameservers[nameserver.String()] = true
		}

		for _, searchDomain := range config.SearchDomains {
			searchDomains[searchDomain] = true
		}
	}

	err := w.resetConfig()
	if err != nil {
		return err
	}

	err = w.setRegistry(nameservers, searchDomains)
	if err != nil {
		return err
	}

	if matchAllDomains {
		searchDomains["."] = true
	}

	return w.setNrptRules(nameservers, searchDomains)
}

func (w *windowsManager) setNrptRules(nameservers map[string]bool, searchDomains map[string]bool) error {
	var nameserver string
	for ns := range nameservers {
		if nameserver == "" {
			nameserver = fmt.Sprintf("\"%s\"", ns)
		} else {
			nameserver = fmt.Sprintf("%s,\"%s\"", nameserver, ns)
		}
	}

	for domain := range searchDomains {
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

func (w *windowsManager) setRegistry(nameservers map[string]bool, searchDomains map[string]bool) error {
	skipIpv4 := true
	skipIpv6 := true
	for ns := range nameservers {
		ip := net.ParseIP(ns)
		if ip.To4() != nil {
			skipIpv4 = false
		}

		if ip.To16() != nil {
			skipIpv6 = false
		}
	}

	var searchDomainsList []string
	for searchDomain := range searchDomains {
		searchDomainsList = append(searchDomainsList, searchDomain)
	}

	if !skipIpv4 {
		err := w.setRegistrySearchList(searchDomainsList, false)
		if err != nil {
			return err
		}
	}

	if !skipIpv6 {
		err := w.setRegistrySearchList(searchDomainsList, true)
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

	searchListStr, _, err := searchListKey.GetStringValue("SearchList")
	searchListStr = strings.TrimSpace(searchListStr)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			err = searchListKey.SetStringValue("SearchList", strings.Join(searchDomains, ","))
			if err != nil {
				return err
			}
		} else {
			return err
		}
	} else {
		_, _, err = searchListKey.GetStringValue("PreNetmakerSearchList")
		if err != nil {
			if errors.Is(err, registry.ErrNotExist) {
				err = searchListKey.SetStringValue("PreNetmakerSearchList", searchListStr)
				if err != nil {
					return err
				}
			} else {
				return err
			}
		}

		if len(searchListStr) > 0 {
			searchDomains = append(searchDomains, strings.Split(searchListStr, ",")...)
		}

		err = searchListKey.SetStringValue("SearchList", strings.Join(searchDomains, ","))
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
	if err != nil {
		return err
	}

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

	return nil
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
		searchList, _, err := globalSearchListKey.GetStringValue("PreNetmakerSearchList")
		if err != nil {
			if !errors.Is(err, registry.ErrNotExist) {
				return err
			}
		} else {
			err = globalSearchListKey.SetStringValue("SearchList", searchList)
			if err != nil {
				return err
			}

			_ = globalSearchListKey.DeleteValue("PreNetmakerSearchList")
		}
	}

	if !skipIpv4 {
		searchList, _, err := ipv4SearchListKey.GetStringValue("PreNetmakerSearchList")
		if err != nil {
			if !errors.Is(err, registry.ErrNotExist) {
				return err
			}
		} else {
			err = ipv4SearchListKey.SetStringValue("SearchList", searchList)
			if err != nil {
				return err
			}

			_ = ipv4SearchListKey.DeleteValue("PreNetmakerSearchList")
		}
	}

	if !skipIpv6 {
		searchList, _, err := ipv6SearchListKey.GetStringValue("PreNetmakerSearchList")
		if err != nil {
			if !errors.Is(err, registry.ErrNotExist) {
				return err
			}
		} else {
			err = ipv6SearchListKey.SetStringValue("SearchList", searchList)
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
		_, _, err = key.GetStringValue("SearchList")
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
