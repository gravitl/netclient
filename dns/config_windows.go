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

// SetupDNSConfig configures DNS for Windows using NRPT rules and interface-specific search lists.
// This implementation:
//   - Uses NRPT (Name Resolution Policy Table) rules to route DNS queries for specific domains
//     to the netclient DNS server, ensuring only netmaker-related queries go to netclient.
//   - Sets DNS server on the interface as a secondary (index 2) server to enable nslookup support
//     without making netclient the primary resolver. The primary resolver remains unchanged.
//   - Sets search lists on interface/system-wide level (not global policy), so netmaker
//     domains are added to the search suffix pool without overriding other interfaces or
//     global policy settings.
//
// Note on nslookup behavior:
//   - ping and other Windows DNS client-based tools automatically append search domains
//   - nslookup will use the netclient DNS server as a fallback (secondary) when the primary
//     DNS server doesn't resolve a query, enabling it to work with netmaker domains
//   - For best results with nslookup, use the full FQDN: nslookup hostname.domain
//   - nslookup can also use search domains by running: nslookup, then "set search", then the hostname
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
			if ns.IsFallback {
				continue
			}

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
		// Use NRPT rules to route DNS queries for specific domains to netclient DNS server
		// This ensures only queries for netmaker domains go to netclient DNS, not all queries
		err := setNrptRule(namespaces, dnsIP)
		if err != nil {
			return err
		}

		// Set DNS server on the interface as secondary (index 2) to enable nslookup support
		// This makes the DNS server available to nslookup without making it the primary resolver
		// The primary resolver remains unchanged, and NRPT rules ensure netmaker domains
		// are routed correctly regardless of DNS server order
		err = setInterfaceDNSServer(dnsIP)
		if err != nil {
			// Log warning but don't fail - NRPT rules still work without interface DNS setting
			slog.Warn("failed to set DNS server on interface for nslookup support", "error", err)
		}

		// Set search list on interface/system-wide level (not global policy)
		// This adds netmaker domains to the search suffix pool without overriding
		// other interfaces or global policy settings
		err = setSearchList(searchList)
		if err != nil {
			return err
		}

		return nil
	} else {
		return resetConfig()
	}
}

func resetConfig() error {
	err := resetSearchList()
	if err != nil {
		return err
	}

	err = resetInterfaceDNSServer()
	if err != nil {
		// Log warning but continue - cleanup is best effort
		slog.Warn("failed to reset DNS server on interface", "error", err)
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
			searchListStr = strings.TrimSpace(preNetmakerSearchList)
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

func resetSearchList() error {
	// Only reset interface/system-wide search lists, never touch global policy
	var skipIpv4, skipIpv6 bool

	ipv4SearchListKey, err := getIpv4SearchListRegistryKey()
	if err != nil {
		skipIpv4 = true
	}

	ipv6SearchListKey, err := getIpv6SearchListRegistryKey()
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

// getSearchListRegistryKey returns interface/system-wide search list registry key
// We intentionally avoid the global policy key (SOFTWARE\Policies\Microsoft\Windows NT\DNSClient)
// to prevent overriding interface-specific settings and system-wide configurations.
// This ensures search domains are added to the interface's search list without affecting
// other interfaces or overriding group policy settings.
func getSearchListRegistryKey(ipv6 bool) (registry.Key, error) {
	// Always use interface/system-wide keys, never global policy key
	// Global policy key overrides all interface-specific settings per MS docs
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

// setNrptRule creates an NRPT rule to route DNS queries for specific domains to the netclient DNS server.
// Note: nslookup on Windows bypasses search domains and doesn't append them automatically.
// To use nslookup with netmaker domains, use the full FQDN: nslookup hostname.domain
// Alternatively, specify the DNS server explicitly: nslookup hostname.domain <netclient-dns-ip>
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

	err = nrptRuleKey.SetDWordValue("Version", 2)
	if err != nil {
		return err
	}

	// Flush DNS cache to ensure NRPT rules take effect immediately
	// This is especially important for nslookup which uses a direct DNS client
	_ = FlushLocalDnsCache()

	return nil
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

// setInterfaceDNSServer sets the DNS server on the netmaker interface as a secondary DNS server
// (index 2) to enable nslookup support without making netclient the primary resolver.
// nslookup will use this DNS server as a fallback, and NRPT rules ensure netmaker domain
// queries are routed correctly regardless of DNS server order.
func setInterfaceDNSServer(dnsIP string) error {
	ifaceName := ncutils.GetInterfaceName()
	if ifaceName == "" {
		return errors.New("interface name not available")
	}

	// Set DNS server as secondary (index 2) so it's available but not primary
	// This allows nslookup to use it while keeping the existing primary DNS server intact
	cmd := fmt.Sprintf("netsh interface ipv4 set dns name=\"%s\" addr=%s index=2", ifaceName, dnsIP)
	_, err := ncutils.RunCmd(cmd, false)
	if err != nil {
		return fmt.Errorf("failed to set DNS server on interface: %w", err)
	}

	slog.Debug("set DNS server on interface for nslookup support", "interface", ifaceName, "dns", dnsIP)
	return nil
}

// resetInterfaceDNSServer removes the netclient DNS server from the interface
func resetInterfaceDNSServer() error {
	ifaceName := ncutils.GetInterfaceName()
	if ifaceName == "" {
		return errors.New("interface name not available")
	}

	// Remove DNS server at index 2 (where we set it)
	cmd := fmt.Sprintf("netsh interface ipv4 delete dns name=\"%s\" addr=all index=2", ifaceName)
	_, err := ncutils.RunCmd(cmd, false)
	if err != nil {
		// Try alternative approach - remove by address if we can get it
		dnsIP, dnsErr := getDnsIp()
		if dnsErr == nil {
			cmd = fmt.Sprintf("netsh interface ipv4 delete dns name=\"%s\" addr=%s", ifaceName, dnsIP)
			_, err = ncutils.RunCmd(cmd, false)
		}
		if err != nil {
			return fmt.Errorf("failed to reset DNS server on interface: %w", err)
		}
	}

	return nil
}
