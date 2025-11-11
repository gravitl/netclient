package dns

import (
	"errors"
	"net"
	"strings"

	"github.com/gravitl/netclient/config"
	dnsconfig "github.com/gravitl/netclient/dns/config"
	"github.com/gravitl/netclient/ncutils"
)

func Configure() error {
	ip, err := getDnsIp()
	if err != nil {
		return err
	}

	var dnsConfig dnsconfig.Config
	dnsConfig.Nameservers = []net.IP{net.ParseIP(ip)}
	dnsConfig.SplitDNS = true

	if config.GetServer(config.CurrServer).DefaultDomain != "" {
		dnsConfig.SearchDomains = append(dnsConfig.SearchDomains, config.GetServer(config.CurrServer).DefaultDomain)
	}

	var matchAllDomains bool
	for _, nameserver := range config.GetServer(config.CurrServer).DnsNameservers {
		if nameserver.MatchDomain == "." {
			matchAllDomains = true
		} else {
			dnsConfig.SearchDomains = append(dnsConfig.SearchDomains, nameserver.MatchDomain)
		}
	}

	if config.Netclient().CurrGwNmIP != nil || matchAllDomains {
		dnsConfig.SplitDNS = false
	}

	return configManager.Configure(ncutils.GetInterfaceName(), dnsConfig)
}

// getDnsIp return the ip address of the dns server
func getDnsIp() (string, error) {
	dnsIp := GetDNSServerInstance().AddrStr
	if dnsIp == "" {
		return "", errors.New("no listener is running")
	}

	if len(config.GetNodes()) == 0 {
		return "", errors.New("no network joint")
	}

	dnsIp = getIpFromServerString(dnsIp)

	return dnsIp, nil
}

// getIpFromServerString returns ip address from the ip:port
// address pair.
func getIpFromServerString(addrStr string) string {
	s := ""
	s = addrStr[0:strings.LastIndex(addrStr, ":")]

	if strings.Contains(s, "[") {
		s = strings.ReplaceAll(s, "[", "")
	}

	if strings.Contains(s, "]") {
		s = strings.ReplaceAll(s, "]", "")
	}

	return s
}
