package config

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

type windowsManager struct{}

func NewManager() (Manager, error) {
	return &windowsManager{}, nil
}

func (w *windowsManager) Configure(config Config) error {
	if len(config.Nameservers) == 0 {
		return w.resetConfig()
	} else {
		var domains []string
		for _, domain := range config.SearchDomains {
			if domain != "." {
				domains = append(domains, domain)
			}
		}

		err := w.setNrptRules(config.Nameservers, config.SearchDomains)
		if err != nil {
			return err
		}

		return w.setRegistry(config.Nameservers, domains)
	}
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

		addCmd := fmt.Sprintf("Add-DnsClientNrptRule -Namespace \"%s\" -NameServers %s -Comment \"Managed by netmaker\"", domain, nameserver)
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
		err := w.setRegistrySearchList(false, searchDomains)
		if err != nil {
			return err
		}
	}

	if !skipIpv6 {
		err := w.setRegistrySearchList(true, searchDomains)
		if err != nil {
			return err
		}
	}

	return nil
}

func (w *windowsManager) setRegistrySearchList(ipv6Family bool, searchDomains []string) error {
	searchListKey, err := w.getRegistrySearchListKey(ipv6Family)
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
	getCmd := fmt.Sprintf("Get-DnsClientNrptRule | Where-Object {$_.Comment -eq \"Managed by netmaker\"} | Select-Object -ExpandProperty Name")
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
	var skipIpv4, skipIpv6 bool
	ipv4SearchListKey, err := w.getRegistrySearchListKey(false)
	if err != nil {
		skipIpv4 = true
	}

	ipv6SearchListKey, err := w.getRegistrySearchListKey(true)
	if err != nil {
		skipIpv6 = true
	}

	defer func() {
		if !skipIpv4 {
			_ = ipv4SearchListKey.Close()
		}

		if !skipIpv6 {
			_ = ipv6SearchListKey.Close()
		}
	}()

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

func (w *windowsManager) getRegistrySearchListKey(ipv6Family bool) (registry.Key, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, registry.ALL_ACCESS)
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

	if ipv6Family {
		return registry.OpenKey(registry.LOCAL_MACHINE, `System\CurrentControlSet\Services\Tcpip6\Parameters`, registry.ALL_ACCESS)
	} else {
		return registry.OpenKey(registry.LOCAL_MACHINE, `System\CurrentControlSet\Services\Tcpip\Parameters`, registry.ALL_ACCESS)
	}
}

func (w *windowsManager) SupportsInterfaceSpecificConfig() bool {
	return false
}
