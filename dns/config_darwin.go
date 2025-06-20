package dns

import (
	"fmt"
	"os"
	"sync"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"golang.org/x/exp/slog"
)

var dnsConfigMutex sync.Mutex

func FlushLocalDnsCache() error {
	_, err := ncutils.RunCmd("dscacheutil -flushcache", false)
	if err != nil {
		slog.Warn("failed to flush local dns cache", "error", err.Error())
		return err
	}

	_, err = ncutils.RunCmd("killall -HUP mDNSResponder", false)
	if err != nil {
		slog.Warn("failed to flush local dns cache", "error", err.Error())
	}

	return err
}

func SetupDNSConfig() error {
	dnsConfigMutex.Lock()
	defer dnsConfigMutex.Unlock()

	// ignore if dns manager is not mDNSResolver
	if config.Netclient().DNSManagerType != DNS_MANAGER_MDNSRESPONDER {
		return nil
	}

	dnsIp, err := getDnsIp()
	if err != nil {
		return err
	}

	domain := config.GetServer(config.CurrServer).DefaultDomain

	err = os.MkdirAll("/etc/resolver/", os.FileMode(0755))
	if err != nil {
		return err
	}

	contents := fmt.Sprintf(`
nameserver %s
`, dnsIp)

	file, err := os.Create("/etc/resolver/" + domain)
	if err != nil {
		return err
	}

	defer file.Close()

	err = file.Chmod(os.FileMode(0755))
	if err != nil {
		return err
	}

	_, err = file.WriteString(contents)
	if err != nil {
		return err
	}

	return FlushLocalDnsCache()
}

func RestoreDNSConfig() error {
	dnsConfigMutex.Lock()
	defer dnsConfigMutex.Unlock()

	domain := config.GetServer(config.CurrServer).DefaultDomain

	_ = os.Remove("/etc/resolver/" + domain)
	return FlushLocalDnsCache()
}

func InitDNSConfig() {
	dnsConfigMutex.Lock()
	defer dnsConfigMutex.Unlock()

	config.Netclient().DNSManagerType = DNS_MANAGER_MDNSRESPONDER
}
