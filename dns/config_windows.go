package dns

import (
	"fmt"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"golang.org/x/exp/slog"
	"golang.org/x/sys/windows/registry"
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
	// ignore if dns manager is not Windows Registry
	if config.Netclient().DNSManagerType != DNS_MANAGER_WINDOWS_REGISTRY {
		return nil
	}

	dnsIp, err := getDnsIp()
	if err != nil {
		return err
	}

	guid := config.Netclient().Host.ID.String()
	if guid == "" {
		guid = config.DefaultHostID
	}

	guid = "{" + guid + "}"

	keyPath := fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%s`, guid)

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

	return nil
}

func RestoreDNSConfig() error {
	return nil
}

func InitDNSConfig() {
	dnsConfigMutex.Lock()
	defer dnsConfigMutex.Unlock()

	config.Netclient().DNSManagerType = DNS_MANAGER_WINDOWS_REGISTRY
}
