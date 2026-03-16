package config

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"

	"github.com/google/uuid"
	"golang.org/x/sys/windows/registry"
)

const (
	nrptRuleMarker = "Managed by netmaker"
)

type windowsManager struct {
	configs      map[string]Config
	nrptRuleName string
	mu           sync.Mutex
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

	w.mu.Lock()
	defer w.mu.Unlock()

	if config.Remove {
		delete(w.configs, iface)

		err := w.resetInterfaceSearchList(iface)
		if err != nil {
			return err
		}
	} else {
		w.configs[iface] = config

		var nameservers []string
		for _, ns := range config.Nameservers {
			nameservers = append(nameservers, ns.String())
		}

		err := w.setInterfaceSearchList(iface, config.SearchDomains, nameservers)
		if err != nil {
			return err
		}
	}

	nameserversMap := make(map[string]bool)
	matchDomainsMap := make(map[string]bool)
	searchDomainsMap := make(map[string]bool)
	var nameservers, searchList, namespaces []string
	var matchAllDomains bool
	for _, _config := range w.configs {
		if !_config.SplitDNS {
			matchAllDomains = true
		}

		for _, ns := range _config.Nameservers {
			nameserver := ns.String()
			_, ok := nameserversMap[nameserver]
			if !ok {
				nameserversMap[nameserver] = true
				nameservers = append(nameservers, nameserver)
			}
		}

		for _, domain := range _config.MatchDomains {
			domain = strings.TrimSuffix(strings.TrimPrefix(domain, "."), ".")

			_, ok := matchDomainsMap[domain]
			if !ok {
				matchDomainsMap[domain] = true
				namespaces = append(namespaces, "."+domain)
			}
		}

		for _, domain := range _config.SearchDomains {
			domain = strings.TrimSuffix(strings.TrimPrefix(domain, "."), ".")

			_, ok := searchDomainsMap[domain]
			if !ok {
				searchDomainsMap[domain] = true
				searchList = append(searchList, domain)
			}
		}
	}

	if matchAllDomains {
		namespaces = append(namespaces, ".")
	}

	if len(namespaces) > 0 {
		err := w.setGlobalSearchList(searchList, nameservers)
		if err != nil {
			return err
		}

		return w.setNrptRule(namespaces, nameservers)
	}

	return w.resetConfig()
}

func (w *windowsManager) resetConfig() error {
	for iface := range w.configs {
		err := w.resetInterfaceSearchList(iface)
		if err != nil {
			return err
		}
	}

	err := w.resetGlobalSearchList()
	if err != nil {
		return err
	}

	return w.resetNrptRule()
}

func (w *windowsManager) setInterfaceSearchList(iface string, searchList, dnsIPs []string) error {
	guid, err := w.getInterfaceGUID(iface)
	if err != nil {
		return err
	}

	err = w.setInterfaceSearchListOnRegistry(guid, searchList, dnsIPs, false)
	if err != nil {
		return err
	}

	return w.setInterfaceSearchListOnRegistry(guid, searchList, dnsIPs, true)
}

func (w *windowsManager) setGlobalSearchList(searchList, dnsIPs []string) error {
	err := w.setSearchListOnRegistry(searchList, dnsIPs, false)
	if err != nil {
		return err
	}

	return w.setSearchListOnRegistry(searchList, dnsIPs, true)
}

func (w *windowsManager) setSearchListOnRegistry(searchDomains, dnsIPs []string, ipv6 bool) error {
	searchListKey, err := w.getSearchListRegistryKey(ipv6)
	if err != nil {
		return err
	}
	defer func() {
		_ = searchListKey.Close()
	}()

	return w.setSearchListOnRegistryKey(searchListKey, searchDomains, dnsIPs)
}

func (w *windowsManager) setInterfaceSearchListOnRegistry(guid string, searchDomains, dnsIPs []string, ipv6 bool) error {
	searchListKey, err := w.getInterfaceSearchListRegistryKey(ipv6, guid)
	if err != nil {
		return err
	}
	defer func() {
		_ = searchListKey.Close()
	}()

	return w.setSearchListOnRegistryKey(searchListKey, searchDomains, dnsIPs)
}

func (w *windowsManager) setSearchListOnRegistryKey(searchListKey registry.Key, searchDomains, dnsIPs []string) error {
	searchListStr, _, err := searchListKey.GetStringValue("SearchList")
	searchListStr = strings.TrimSpace(searchListStr)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			err = searchListKey.SetStringValue("SearchList", strings.Join(searchDomains, ","))
			if err != nil {
				return err
			}

			err = searchListKey.SetStringValue("PreNetmakerSearchList", "")
			if err != nil {
				return err
			}
		} else {
			return err
		}
	} else {
		preNetmakerSearchList, _, err := searchListKey.GetStringValue("PreNetmakerSearchList")
		if err != nil {
			if errors.Is(err, registry.ErrNotExist) {
				err = searchListKey.SetStringValue("PreNetmakerSearchList", searchListStr)
				if err != nil {
					return err
				}
			} else {
				return err
			}
		} else {
			searchListStr = preNetmakerSearchList
		}

		if len(searchListStr) > 0 {
			searchDomains = append(searchDomains, strings.Split(searchListStr, ",")...)
		}

		err = searchListKey.SetStringValue("SearchList", strings.Join(searchDomains, ","))
		if err != nil {
			return err
		}
	}

	nameserverStr, _, err := searchListKey.GetStringValue("NameServer")
	nameserverStr = strings.TrimSpace(nameserverStr)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			err = searchListKey.SetStringValue("NameServer", strings.Join(dnsIPs, ","))
			if err != nil {
				return err
			}

			err = searchListKey.SetStringValue("PreNetmakerNameServer", "")
			if err != nil {
				return err
			}
		} else {
			return err
		}
	} else {
		preNetmakerNameServer, _, err := searchListKey.GetStringValue("PreNetmakerNameServer")
		if err != nil {
			if errors.Is(err, registry.ErrNotExist) {
				err = searchListKey.SetStringValue("PreNetmakerNameServer", nameserverStr)
				if err != nil {
					return err
				}
			} else {
				return err
			}
		} else {
			nameserverStr = strings.TrimSpace(preNetmakerNameServer)
		}

		nameservers := dnsIPs
		if len(nameserverStr) > 0 {
			nameservers = append(nameservers, strings.Split(nameserverStr, ",")...)
		}

		err = searchListKey.SetStringValue("NameServer", strings.Join(nameservers, ","))
		if err != nil {
			return err
		}
	}

	return nil
}

func (w *windowsManager) resetInterfaceSearchList(iface string) error {
	guid, err := w.getInterfaceGUID(iface)
	if err != nil {
		return err
	}

	var skipIpv4, skipIpv6 bool
	ipv4InterfaceSearchListKey, err := w.getIpv4InterfaceSearchListRegistryKey(guid)
	if err != nil {
		skipIpv4 = true
	}

	ipv6InterfaceSearchListKey, err := w.getIpv6InterfaceSearchListRegistryKey(guid)
	if err != nil {
		skipIpv6 = true
	}

	defer func() {
		if !skipIpv4 {
			_ = ipv4InterfaceSearchListKey.Close()
		}

		if !skipIpv6 {
			_ = ipv6InterfaceSearchListKey.Close()
		}
	}()

	if !skipIpv4 {
		err = w.resetSearchListOnRegistryKey(ipv4InterfaceSearchListKey)
		if err != nil {
			return err
		}
	}

	if !skipIpv6 {
		err = w.resetSearchListOnRegistryKey(ipv6InterfaceSearchListKey)
		if err != nil {
			return err
		}
	}

	return nil
}

func (w *windowsManager) resetGlobalSearchList() error {
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
		err = w.resetSearchListOnRegistryKey(globalSearchListKey)
		if err != nil {
			return err
		}
	}

	if !skipIpv4 {
		err = w.resetSearchListOnRegistryKey(ipv4SearchListKey)
		if err != nil {
			return err
		}
	}

	if !skipIpv6 {
		err = w.resetSearchListOnRegistryKey(ipv6SearchListKey)
		if err != nil {
			return err
		}
	}

	return nil
}

func (w *windowsManager) resetSearchListOnRegistryKey(searchListKey registry.Key) error {
	searchList, _, err := searchListKey.GetStringValue("PreNetmakerSearchList")
	if err != nil {
		if !errors.Is(err, registry.ErrNotExist) {
			return err
		}
	} else {
		err = searchListKey.SetStringValue("SearchList", searchList)
		if err != nil {
			return err
		}

		_ = searchListKey.DeleteValue("PreNetmakerSearchList")
	}

	nameserver, _, err := searchListKey.GetStringValue("PreNetmakerNameServer")
	if err != nil {
		if !errors.Is(err, registry.ErrNotExist) {
			return err
		}
	} else {
		err = searchListKey.SetStringValue("NameServer", nameserver)
		if err != nil {
			return err
		}

		_ = searchListKey.DeleteValue("PreNetmakerNameServer")
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

func (w *windowsManager) getInterfaceSearchListRegistryKey(ipv6 bool, guid string) (registry.Key, error) {
	if ipv6 {
		return w.getIpv6InterfaceSearchListRegistryKey(guid)
	}

	return w.getIpv4InterfaceSearchListRegistryKey(guid)
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

func (w *windowsManager) getIpv4InterfaceSearchListRegistryKey(guid string) (registry.Key, error) {
	path := fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%s`, guid)
	return registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
}

func (w *windowsManager) getIpv6InterfaceSearchListRegistryKey(guid string) (registry.Key, error) {
	path := fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\%s`, guid)
	return registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
}

func (w *windowsManager) setNrptRule(namespaces, nameservers []string) error {
	nrptRuleKey, err := w.getNrptRuleRegistryKey()
	if err != nil {
		return err
	}
	defer func() {
		_ = nrptRuleKey.Close()
	}()

	err = nrptRuleKey.SetStringsValue("Name", namespaces)
	if err != nil {
		return err
	}

	err = nrptRuleKey.SetStringValue("GenericDNSServers", strings.Join(nameservers, ";"))
	if err != nil {
		return err
	}

	err = nrptRuleKey.SetStringValue("Comment", nrptRuleMarker)
	if err != nil {
		return err
	}

	err = nrptRuleKey.SetDWordValue("ConfigOptions", 8)
	if err != nil {
		return err
	}

	return nrptRuleKey.SetDWordValue("Version", 2)
}

func (w *windowsManager) resetNrptRule() error {
	if w.nrptRuleName == "" {
		globalKey, err := w.getGlobalNrptRuleRegistryKey()
		if err == nil {
			_ = w.findAndResetNrptRule(globalKey)
			_ = globalKey.Close()
		}

		localKey, err := w.getLocalNrptRuleRegistryKey()
		if err == nil {
			_ = w.findAndResetNrptRule(localKey)
			_ = localKey.Close()
		}
	} else {
		globalKey, err := w.getGlobalNrptRuleRegistryKey()
		if err == nil {
			_ = registry.DeleteKey(globalKey, w.nrptRuleName)
			_ = globalKey.Close()
		}

		localKey, err := w.getLocalNrptRuleRegistryKey()
		if err == nil {
			_ = registry.DeleteKey(localKey, w.nrptRuleName)
			_ = localKey.Close()
		}
	}

	return nil
}

func (w *windowsManager) findAndResetNrptRule(key registry.Key) error {
	keepLooking := true
	for keepLooking {
		subKeyNames, err := key.ReadSubKeyNames(10)
		if err != nil {
			if err == io.EOF {
				keepLooking = false
			} else {
				return err
			}
		}
		for _, subKeyName := range subKeyNames {
			subKey, err := registry.OpenKey(key, subKeyName, registry.ALL_ACCESS)
			if err != nil {
				return err
			}

			comment, _, err := subKey.GetStringValue("Comment")
			if err == nil {
				if comment == nrptRuleMarker {
					_ = registry.DeleteKey(key, subKeyName)
				}
			}
			_ = subKey.Close()
		}
	}

	return nil
}

func (w *windowsManager) getNrptRuleRegistryKey() (registry.Key, error) {
	key, err := w.getGlobalNrptRuleRegistryKey()
	if err != nil {
		if !errors.Is(err, registry.ErrNotExist) {
			return 0, err
		}
	} else {
		defer func() {
			_ = key.Close()
		}()

		ruleName := w.nrptRuleName
		if ruleName == "" {
			ruleName = "{" + strings.ToUpper(uuid.NewString()) + "}"
		}

		ruleKey, _, err := registry.CreateKey(key, ruleName, registry.ALL_ACCESS)
		if err != nil {
			return 0, err
		}

		w.nrptRuleName = ruleName
		return ruleKey, nil
	}

	ruleName := w.nrptRuleName
	if ruleName == "" {
		ruleName = "{" + strings.ToUpper(uuid.NewString()) + "}"
	}

	key, _, err = registry.CreateKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\DnsCache\Parameters\DnsPolicyConfig\`+ruleName, registry.ALL_ACCESS)
	if err != nil {
		return 0, err
	}

	w.nrptRuleName = ruleName
	return key, nil
}

func (w *windowsManager) getGlobalNrptRuleRegistryKey() (registry.Key, error) {
	return registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\WindowsNT\DNSClient\DnsPolicyConfig`, registry.ALL_ACCESS)
}

func (w *windowsManager) getLocalNrptRuleRegistryKey() (registry.Key, error) {
	return registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\DnsCache\Parameters\DnsPolicyConfig`, registry.ALL_ACCESS)
}

func (w *windowsManager) getInterfaceGUID(name string) (string, error) {
	getAdapterCmd := fmt.Sprintf("(Get-NetAdapter -Name '%s').InterfaceGuid", name)
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", getAdapterCmd)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	guid := strings.TrimSpace(string(output))
	return guid, nil
}
