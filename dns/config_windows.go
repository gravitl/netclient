package dns

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"golang.org/x/exp/slog"
	"golang.org/x/sys/windows/registry"
)

const (
	nrptRuleMarker = "Managed by netmaker"
)

var dnsConfigMutex sync.Mutex
var nrptRuleName string

func FlushLocalDnsCache() error {
	_, err := ncutils.RunCmd("ipconfig /flushdns", false)
	if err != nil {
		slog.Warn("failed to flush local dns cache", "error", err.Error())
	}

	return err
}

func SetupDNSConfig() error {
	dnsConfigMutex.Lock()
	defer dnsConfigMutex.Unlock()

	// ignore if dns manager is not Windows Registry
	if config.Netclient().DNSManagerType != DNS_MANAGER_WINDOWS_REGISTRY {
		return nil
	}

	dnsIp, err := getDnsIp()
	if err != nil {
		return err
	}

	matchDomainsMap := make(map[string]bool)
	searchDomainsMap := make(map[string]bool)
	var matchAllDomains bool
	server := config.GetServer(config.CurrServer)
	if server != nil {
		if server.DefaultDomain != "" {
			domain := strings.TrimSuffix(strings.TrimPrefix(server.DefaultDomain, "."), ".")
			matchDomainsMap[domain] = true
			searchDomainsMap[domain] = true
		}

		for _, ns := range server.DnsNameservers {
			if ns.MatchDomain != "." {
				domain := strings.TrimSuffix(strings.TrimPrefix(ns.MatchDomain, "."), ".")
				matchDomainsMap[domain] = true
				if ns.IsSearchDomain {
					searchDomainsMap[domain] = true
				}
			} else {
				matchAllDomains = true
			}
		}
	}

	return configure(dnsIp, matchDomainsMap, searchDomainsMap, matchAllDomains)
}

func RestoreDNSConfig() error {
	return resetConfig()
}

func InitDNSConfig() {
	dnsConfigMutex.Lock()
	defer dnsConfigMutex.Unlock()

	config.Netclient().DNSManagerType = DNS_MANAGER_WINDOWS_REGISTRY
}

func configure(dnsIP string, matchDomainsMap map[string]bool, searchDomainsMap map[string]bool, matchAllDomains bool) error {
	var searchList, namespaces []string
	for matchDomain := range matchDomainsMap {
		namespaces = append(namespaces, "."+matchDomain)
	}

	for searchDomain := range searchDomainsMap {
		searchList = append(searchList, searchDomain)
	}

	if matchAllDomains {
		namespaces = append(namespaces, ".")
	}

	if len(namespaces) > 0 {
		err := setSearchList(searchList)
		if err != nil {
			return err
		}

		return setNrptRule(namespaces, dnsIP)
	} else {
		return resetConfig()
	}
}

func resetConfig() error {
	err := resetSearchList()
	if err != nil {
		return err
	}

	return resetNrptRules()
}

func setSearchList(searchList []string) error {
	err := setSearchListOnRegistry(searchList, false)
	if err != nil {
		return err
	}

	return setSearchListOnRegistry(searchList, true)
}

func setSearchListOnRegistry(searchDomains []string, ipv6 bool) error {
	searchListKey, err := getSearchListRegistryKey(ipv6)
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

	reset(false)
	reset(true)
	return nil
}

func reset(ipv6 bool) {
	guid := config.Netclient().Host.ID.String()
	if guid == "" {
		guid = config.DefaultHostID
	}

	guid = "{" + guid + "}"

	keyPath := fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\%s`, guid)
	globalKeyPath := fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`)
	if ipv6 {
		keyPath = fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%s`, guid)
		globalKeyPath = fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`)
	}

	_ = resetInterface(keyPath)
	_ = resetGlobal(globalKeyPath)
}

func resetInterface(keyPath string) error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	err = key.SetStringValue("NameServer", "")
	if err != nil {
		return err
	}

	return key.SetStringValue("SearchList", "")
}

func resetGlobal(globalKeyPath string) error {
	globalKey, err := registry.OpenKey(registry.LOCAL_MACHINE, globalKeyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer globalKey.Close()

	return globalKey.SetStringValue("SearchList", "")
}

func resetSearchList() error {
	var skipGlobal, skipIpv4, skipIpv6 bool
	globalSearchListKey, err := getGlobalSearchListRegistryKey()
	if err != nil {
		skipGlobal = true
	}

	ipv4SearchListKey, err := getIpv4SearchListRegistryKey()
	if err != nil {
		skipIpv4 = true
	}

	ipv6SearchListKey, err := getIpv6SearchListRegistryKey()
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

func getSearchListRegistryKey(ipv6 bool) (registry.Key, error) {
	key, err := getGlobalSearchListRegistryKey()
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
		return getIpv6SearchListRegistryKey()
	}

	return getIpv4SearchListRegistryKey()
}

func getGlobalSearchListRegistryKey() (registry.Key, error) {
	return registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, registry.ALL_ACCESS)
}

func getIpv4SearchListRegistryKey() (registry.Key, error) {
	return registry.OpenKey(registry.LOCAL_MACHINE, `System\CurrentControlSet\Services\Tcpip\Parameters`, registry.ALL_ACCESS)
}

func getIpv6SearchListRegistryKey() (registry.Key, error) {
	return registry.OpenKey(registry.LOCAL_MACHINE, `System\CurrentControlSet\Services\Tcpip6\Parameters`, registry.ALL_ACCESS)
}

func setNrptRule(namespaces []string, nameservers string) error {
	nrptRuleKey, err := getNrptRuleRegistryKey()
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

func resetNrptRules() error {
	if nrptRuleName == "" {
		globalKey, err := getGlobalNrptRuleRegistryKey()
		if err == nil {
			_ = findAndResetNrptRule(globalKey)
			_ = globalKey.Close()
		}

		localKey, err := getLocalNrptRuleRegistryKey()
		if err == nil {
			_ = findAndResetNrptRule(localKey)
			_ = localKey.Close()
		}
	} else {
		globalKey, err := getGlobalNrptRuleRegistryKey()
		if err == nil {
			_ = registry.DeleteKey(globalKey, nrptRuleName)
			_ = globalKey.Close()
		}

		localKey, err := getLocalNrptRuleRegistryKey()
		if err == nil {
			_ = registry.DeleteKey(localKey, nrptRuleName)
			_ = localKey.Close()
		}
	}

	return nil
}

func findAndResetNrptRule(key registry.Key) error {
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

func getNrptRuleRegistryKey() (registry.Key, error) {
	key, err := getGlobalNrptRuleRegistryKey()
	if err != nil {
		if !errors.Is(err, registry.ErrNotExist) {
			return 0, err
		}
	} else {
		defer func() {
			_ = key.Close()
		}()

		ruleName := nrptRuleName
		if ruleName == "" {
			ruleName = "{" + strings.ToUpper(uuid.NewString()) + "}"
		}

		ruleKey, _, err := registry.CreateKey(key, ruleName, registry.ALL_ACCESS)
		if err != nil {
			return 0, err
		}

		nrptRuleName = ruleName
		return ruleKey, nil
	}

	ruleName := nrptRuleName
	if ruleName == "" {
		ruleName = "{" + strings.ToUpper(uuid.NewString()) + "}"
	}

	key, _, err = registry.CreateKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\DnsCache\Parameters\DnsPolicyConfig\`+ruleName, registry.ALL_ACCESS)
	if err != nil {
		return 0, err
	}

	nrptRuleName = ruleName
	return key, nil
}

func getGlobalNrptRuleRegistryKey() (registry.Key, error) {
	return registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\WindowsNT\DNSClient\DnsPolicyConfig`, registry.ALL_ACCESS)
}

func getLocalNrptRuleRegistryKey() (registry.Key, error) {
	return registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\DnsCache\Parameters\DnsPolicyConfig`, registry.ALL_ACCESS)
}
