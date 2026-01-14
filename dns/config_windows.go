package dns

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"time"

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

	err = configure(dnsIp, matchDomainsMap, searchDomainsMap, matchAllDomains)
	if err != nil {
		return err
	}

	// Mark interface as corporate/domain-connected for Intranet classification
	// This enables RDP Gateway bypass (like Pritunl does)
	// Retry here as a fallback in case it wasn't set during interface creation
	if runtime.GOOS == "windows" {
		markInterfaceForIntranetClassification()
	}

	return nil
}

// markInterfaceForIntranetClassification marks the WireGuard interface as corporate/domain-connected
// This is a helper function to avoid circular imports with wireguard package
func markInterfaceForIntranetClassification() {
	idString := config.Netclient().Host.ID.String()
	if idString == "" {
		idString = config.DefaultHostID
	}

	// Retry up to 3 times with delays (interface should be registered by now)
	for i := 0; i < 3; i++ {
		if i > 0 {
			time.Sleep(time.Duration(i) * time.Second)
		}

		adapterPath := fmt.Sprintf(`SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{%s}\Connection`, strings.ToUpper(idString))
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, adapterPath, registry.ALL_ACCESS)
		if err != nil {
			if i < 2 {
				slog.Debug("interface registry key not found, retrying", "attempt", i+1)
				continue
			}
			slog.Debug("interface registry key not found after retries", "error", err)
			return
		}

		// Set Type = 6 (Corporate/Enterprise network) for Intranet classification
		// NOTE: NetworkCategory can show "Public" but Type=6 enables Intranet classification for RDP Gateway bypass
		// This is what Pritunl does - it works even with NetworkCategory: Public because Type=6 is set
		err = key.SetDWordValue("Type", 6)
		if err == nil {
			// Also set DomainType and MediaSubType if possible
			_ = key.SetDWordValue("DomainType", 1)
			_ = key.SetDWordValue("MediaSubType", 2)

			// Verify the registry value was set correctly
			typeVal, _, _ := key.GetIntegerValue("Type")
			if typeVal == 6 {
				slog.Info("registry Type=6 set successfully (enables Intranet classification for RDP Gateway bypass)")
			}
		}
		key.Close()

		if err == nil {
			// NOTE: NetworkCategory doesn't matter for RDP Gateway bypass - Pritunl works with NetworkCategory: Public
			// The registry Type=6 is what enables Intranet classification, not the NetworkCategory
			// However, we still try to set it to Private and restart NLA to ensure Windows picks up the registry changes
			interfaceName := ncutils.GetInterfaceName()
			if interfaceName != "" {
				// Try to set network profile to Private (optional - Type=6 is what matters)
				// This helps ensure Windows recognizes the interface, but Type=6 is the key for Intranet classification
				psCmd := fmt.Sprintf(`powershell -Command "$ErrorActionPreference = 'Stop'; try { $profile = Get-NetConnectionProfile -InterfaceAlias '%s' -ErrorAction Stop; if ($profile.NetworkCategory -eq 'Public') { Set-NetConnectionProfile -InterfaceAlias '%s' -NetworkCategory Private -ErrorAction Stop; Write-Host ('NetworkCategory set to Private') } else { Write-Host ('NetworkCategory: ' + $profile.NetworkCategory) } } catch { Write-Host ('Note: ' + $_.Exception.Message) }"`, interfaceName, interfaceName)
				out, psErr := ncutils.RunCmd(psCmd, false)
				if psErr != nil {
					slog.Debug("PowerShell network profile command completed", "output", out)
				} else {
					slog.Debug("PowerShell network profile command completed", "output", strings.TrimSpace(out))
				}

				// Restart NLA service to force Windows to re-evaluate network classification
				// This helps Windows pick up the registry changes (Type=6, DomainType=1)
				// Even if NetworkCategory shows Public, Type=6 enables Intranet classification (like Pritunl)
				nlaRestartCmd := `powershell -Command "try { Restart-Service -Name NlaSvc -ErrorAction Stop; Write-Host 'NLA service restarted' } catch { Write-Host ('NLA restart: ' + $_.Exception.Message) }"`
				nlaOut, nlaErr := ncutils.RunCmd(nlaRestartCmd, false)
				if nlaErr != nil {
					slog.Debug("NLA service restart attempted (may require admin privileges)", "output", nlaOut)
				} else {
					slog.Info("restarted NLA service to refresh network classification")
				}

				// Trigger network change notification
				refreshCmd := `powershell -Command "[System.Net.NetworkInformation.NetworkChange]::NetworkAddressChanged; Start-Sleep -Milliseconds 500"`
				_, _ = ncutils.RunCmd(refreshCmd, false)
			}
			slog.Info("marked WireGuard interface as corporate/domain-connected for Intranet classification (RDP Gateway bypass enabled)")
			return
		}

		if i < 2 {
			slog.Debug("failed to mark interface as corporate, retrying", "attempt", i+1, "error", err)
		} else {
			slog.Warn("failed to mark interface as corporate after retries (RDP Gateway bypass may not work)", "error", err)
		}
	}
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
		err := setSearchList(searchList, dnsIP)
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

func setSearchList(searchList []string, dnsIP string) error {
	err := setSearchListOnRegistry(searchList, dnsIP, false)
	if err != nil {
		return err
	}

	err = setSearchListOnRegistry(searchList, dnsIP, true)
	if err != nil {
		return err
	}

	err = setInterfaceSearchListOnRegistry(config.Netclient().Host.ID.String(), searchList, dnsIP, false)
	if err != nil {
		return err
	}

	return setInterfaceSearchListOnRegistry(config.Netclient().Host.ID.String(), searchList, dnsIP, true)
}

func setSearchListOnRegistry(searchDomains []string, dnsIP string, ipv6 bool) error {
	searchListKey, err := getSearchListRegistryKey(ipv6)
	if err != nil {
		return err
	}
	defer func() {
		_ = searchListKey.Close()
	}()

	return setSearchListOnRegistryKey(searchListKey, searchDomains, dnsIP)
}

func setInterfaceSearchListOnRegistry(guid string, searchDomains []string, dnsIP string, ipv6 bool) error {
	searchListKey, err := getInterfaceSearchListRegistryKey(ipv6, guid)
	if err != nil {
		return err
	}
	defer func() {
		_ = searchListKey.Close()
	}()

	return setSearchListOnRegistryKey(searchListKey, searchDomains, dnsIP)
}

func setSearchListOnRegistryKey(searchListKey registry.Key, searchDomains []string, dnsIP string) error {
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

	nameserverStr, _, err := searchListKey.GetStringValue("NameServer")
	nameserverStr = strings.TrimSpace(nameserverStr)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			err = searchListKey.SetStringValue("NameServer", dnsIP)
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

		nameservers := []string{dnsIP}
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

func resetSearchList() error {
	var skipGlobal, skipIpv4, skipIpv6, skipInterfaceIpv4, skipInterfaceIpv6 bool
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

	ipv4InterfaceSearchListKey, err := getIpv4InterfaceSearchListRegistryKey(config.Netclient().Host.ID.String())
	if err != nil {
		skipInterfaceIpv4 = true
	}

	ipv6InterfaceSearchListKey, err := getIpv6InterfaceSearchListRegistryKey(config.Netclient().Host.ID.String())
	if err != nil {
		skipInterfaceIpv6 = true
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

		if !skipInterfaceIpv4 {
			_ = ipv4InterfaceSearchListKey.Close()
		}

		if !skipInterfaceIpv6 {
			_ = ipv6InterfaceSearchListKey.Close()
		}
	}()

	if !skipGlobal {
		err = resetSearchListOnRegistryKey(globalSearchListKey)
		if err != nil {
			return err
		}
	}

	if !skipIpv4 {
		err = resetSearchListOnRegistryKey(ipv4SearchListKey)
		if err != nil {
			return err
		}
	}

	if !skipIpv6 {
		err = resetSearchListOnRegistryKey(ipv6SearchListKey)
		if err != nil {
			return err
		}
	}

	if !skipInterfaceIpv4 {
		err = resetSearchListOnRegistryKey(ipv4InterfaceSearchListKey)
		if err != nil {
			return err
		}
	}

	if !skipInterfaceIpv6 {
		err = resetSearchListOnRegistryKey(ipv6InterfaceSearchListKey)
		if err != nil {
			return err
		}
	}

	return nil
}

func resetSearchListOnRegistryKey(searchListKey registry.Key) error {
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

func getInterfaceSearchListRegistryKey(ipv6 bool, guid string) (registry.Key, error) {
	if ipv6 {
		return getIpv6InterfaceSearchListRegistryKey(guid)
	}

	return getIpv4InterfaceSearchListRegistryKey(guid)
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

func getIpv4InterfaceSearchListRegistryKey(guid string) (registry.Key, error) {
	path := fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{%s}`, guid)
	return registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
}

func getIpv6InterfaceSearchListRegistryKey(guid string) (registry.Key, error) {
	path := fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{%s}`, guid)
	return registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
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

	// ConfigOptions = 8 (0x08) enables the NRPT rule
	// This works together with interface Type=6 (corporate) to enable Intranet classification
	// Intranet classification allows RDP to bypass RD Gateway for destinations over VPN
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
