package dns

import (
	"fmt"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"golang.org/x/exp/slog"
	"golang.org/x/sys/windows/registry"
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

	_, err = ncutils.RunCmd(
		fmt.Sprintf(
			"Set-DnsClientNrptRule -Namespace \"%s\" -NameServers \"%s\"",
			config.GetServer(config.CurrServer).DefaultDomain,
			dnsIp,
		),
		false,
	)
	if err != nil {
		return err
	}

	return nil
}

func RestoreDNSConfig() error {
	output, err := ncutils.RunCmd(
		"Get-DnsClientNrptRule | Select-Object Name, @{Name='Namespace';Expression={$_.Namespace -join ';'}}, @{Name='NameServers';Expression={$_.NameServers -join ';'}} | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1",
		false,
	)
	if err != nil {
		return err
	}

	dnsIp, err := getDnsIp()
	if err != nil {
		return err
	}

	lines := strings.Split(output, "\r\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if len(line) == 0 {
			continue
		}

		parts := strings.Split(output, ",")

		if len(parts) != 3 {
			continue
		}

		name := strings.TrimSpace(parts[0])

		namespace := strings.TrimSpace(parts[1])
		namespace = strings.Trim(namespace, "\"")

		nameserver := strings.TrimSpace(parts[2])
		nameserver = strings.Trim(nameserver, "\"")

		if namespace != config.GetServer(config.CurrServer).DefaultDomain &&
			nameserver != dnsIp {
			continue
		}

		_, err = ncutils.RunCmd(
			fmt.Sprintf(
				"Remove-DnsClientNrptRule -Name %s -Force",
				name,
			),
			false,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func InitDNSConfig() {
	dnsConfigMutex.Lock()
	defer dnsConfigMutex.Unlock()

	config.Netclient().DNSManagerType = DNS_MANAGER_WINDOWS_REGISTRY
}
