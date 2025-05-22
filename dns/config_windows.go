package dns

import (
	"fmt"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"golang.org/x/exp/slog"
	"golang.org/x/sys/windows/registry"
	"net/netip"
	"strings"
	"sync"
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
	if config.GetServer(config.CurrServer).DefaultDomain != "" {
		domains = append(domains, config.GetServer(config.CurrServer).DefaultDomain)
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
	return nil
}

func InitDNSConfig() {
	dnsConfigMutex.Lock()
	defer dnsConfigMutex.Unlock()

	config.Netclient().DNSManagerType = DNS_MANAGER_WINDOWS_REGISTRY
}
