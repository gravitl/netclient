package dns

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"golang.org/x/exp/slog"
	"golang.org/x/sys/windows/registry"
)

var dnsConfigMutex sync.Mutex

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

	ip, err := netip.ParseAddr(dnsIp)
	if err != nil {
		return err
	}

	guid := config.Netclient().Host.ID.String()
	if guid == "" {
		guid = config.DefaultHostID
	}

	guid = "{" + guid + "}"

	keyPath := ""
	if ip.Is6() {
		keyPath = fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\%s`, guid)
	} else {
		keyPath = fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%s`, guid)
	}

	// open registry key with permissions to set value
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	err = key.SetStringValue("NameServer", dnsIp)
	if err != nil {
		return err
	}

	var domains []string
	server := config.GetServer(config.CurrServer)
	if server != nil {
		if server.DefaultDomain != "" {
			domains = append(domains, server.DefaultDomain)
		}

		for _, ns := range server.DnsNameservers {
			if ns.MatchDomain != "." {
				domains = append(domains, ns.MatchDomain)
			}
		}
	}

	if config.Netclient().DNSSearch != "" {
		domains = append(domains, config.Netclient().DNSSearch)
	}

	err = key.SetStringValue("SearchList", strings.Join(domains, ","))
	if err != nil {
		return err
	}

	globalKeyPath := ""
	if ip.Is6() {
		globalKeyPath = fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`)
	} else {
		globalKeyPath = fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`)
	}

	globalKey, err := registry.OpenKey(registry.LOCAL_MACHINE, globalKeyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer globalKey.Close()

	return globalKey.SetStringValue("SearchList", strings.Join(domains, ","))
}

func RestoreDNSConfig() error {
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

func InitDNSConfig() {
	dnsConfigMutex.Lock()
	defer dnsConfigMutex.Unlock()

	config.Netclient().DNSManagerType = DNS_MANAGER_WINDOWS_REGISTRY
}
