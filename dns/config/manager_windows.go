package config

import (
	"errors"
	"fmt"
	"io"
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

type searchListFamily int

const (
	ipv4 searchListFamily = iota
	ipv6
	both
)

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

	// registry updates only.

	// 1. set search lists.
	// each search domain we have gets added to the SearchList, except "."
	// 2. set domain matching.
	// for each domain, we create a list of nameservers that can resolve it.
	// additionally for !split dns, we set nameserver for the "." domain.

	// remove
	// each search domain part of the interface is affected.

	if config.Remove {
		delete(w.configs, iface)
	} else {
		w.configs[iface] = config
	}

	skipIpv4 := true
	skipIpv6 := true
	nameservers := make(map[string]bool)
	searchDomains := make(map[string]bool)
	var searchList, namespaces []string
	var matchAllDomains bool
	var nameserversStrBuilder strings.Builder
	for _, config := range w.configs {
		if !config.SplitDNS {
			matchAllDomains = true
		}

		for _, ns := range config.Nameservers {
			nameserver := ns.String()
			_, ok := nameservers[nameserver]
			if !ok {
				nameservers[nameserver] = true
				if ns.To4() != nil {
					skipIpv4 = false
				}

				if ns.To16() != nil {
					skipIpv6 = false
				}

				if nameserversStrBuilder.Len() == 0 {
					nameserversStrBuilder.WriteString(nameserver)
				} else {
					nameserversStrBuilder.WriteString(";")
					nameserversStrBuilder.WriteString(nameserver)
				}
			}
		}

		for _, searchDomain := range config.SearchDomains {
			searchDomain = strings.TrimSuffix(strings.TrimPrefix(searchDomain, "."), ".")

			_, ok := searchDomains[searchDomain]
			if !ok {
				searchDomains[searchDomain] = true
				searchList = append(searchList, searchDomain)
				namespaces = append(namespaces, "."+searchDomain)
			}
		}

	}

	if matchAllDomains {
		namespaces = append(namespaces, ".")
	}

	if len(searchDomains) > 0 || matchAllDomains {
		var family searchListFamily
		if skipIpv4 == skipIpv6 {
			family = both
		} else if !skipIpv4 {
			family = ipv4
		} else {
			family = ipv6
		}

		err := w.setSearchList(searchList, family)
		if err != nil {
			return err
		}

		if matchAllDomains {
			searchDomains["."] = true
		}

		return w.setNrptRule(namespaces, nameserversStrBuilder.String())
	} else {
		return w.resetConfig()
	}
}

func (w *windowsManager) resetConfig() error {
	err := w.resetSearchList()
	if err != nil {
		return err
	}

	return w.resetNrptRules()
}

func (w *windowsManager) setSearchList(searchList []string, family searchListFamily) error {
	if family == ipv4 || family == both {
		err := w.setSearchListOnRegistry(searchList, false)
		if err != nil {
			return err
		}
	}

	if family == ipv6 || family == both {
		err := w.setSearchListOnRegistry(searchList, true)
		if err != nil {
			return err
		}
	}

	return nil
}

func (w *windowsManager) setSearchListOnRegistry(searchDomains []string, ipv6 bool) error {
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

func (w *windowsManager) resetSearchList() error {
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

func (w *windowsManager) setNrptRule(namespaces []string, nameservers string) error {
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

	err = nrptRuleKey.SetStringValue("GenericDNSServers", nameservers)
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

func (w *windowsManager) resetNrptRules() error {
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
