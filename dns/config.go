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
	server := config.GetServer(config.CurrServer)
	if server == nil {
		return errors.New("server not configured")
	}

	ips, err := getDnsIps()
	if err != nil {
		return err
	}

	var dnsConfig dnsconfig.Config
	nameserverIPsMap := make(map[string]bool)
	dnsConfig.SplitDNS = true

	if server.DefaultDomain != "" {
		dnsConfig.MatchDomains = append(dnsConfig.MatchDomains, server.DefaultDomain)
		dnsConfig.SearchDomains = append(dnsConfig.SearchDomains, server.DefaultDomain)
	}

	var matchAllDomains bool
	for _, nameserver := range server.DnsNameservers {
		if !nameserver.IsFallback {
			if nameserver.MatchDomain == "." {
				matchAllDomains = true
			} else {
				dnsConfig.MatchDomains = append(dnsConfig.MatchDomains, nameserver.MatchDomain)
				if nameserver.IsSearchDomain {
					dnsConfig.SearchDomains = append(dnsConfig.SearchDomains, nameserver.MatchDomain)
				}
				if nameserver.IsADDomain {
					for _, nameserverIP := range nameserver.IPs {
						_, ok := nameserverIPsMap[nameserverIP]
						if !ok {
							dnsConfig.Nameservers = append(dnsConfig.Nameservers, net.ParseIP(nameserverIP))
							nameserverIPsMap[nameserverIP] = true
						}
					}
				}
			}
		}
	}

	// AD domain nameservers should always be prioritized before gateway DNS.
	for _, ip := range ips {
		if _, ok := nameserverIPsMap[ip]; !ok {
			dnsConfig.Nameservers = append(dnsConfig.Nameservers, net.ParseIP(ip))
			nameserverIPsMap[ip] = true
		}
	}

	if config.Netclient().CurrGwNmIP != nil || matchAllDomains {
		dnsConfig.SplitDNS = false
	}

	return configManager.Configure(ncutils.GetInterfaceName(), dnsConfig)
}

// getDnsIps returns every address the local DNS listener is serving on, in the
// order they should be handed to the resolver. All of them must be published:
// the listener binds whichever families the node has, and publishing only the
// last one leaves dual-stack nodes with an IPv6-only nameserver that a host with
// IPv6 restricted cannot reach at all.
//
// A loopback listener answers regardless of tunnel state, so it stays first
// where one exists (macOS); otherwise IPv4 leads.
func getDnsIps() ([]string, error) {
	addrs := GetDNSServerInstance().AddrList
	if len(addrs) == 0 {
		return nil, errors.New("no listener is running")
	}

	if len(config.GetNodes()) == 0 {
		return nil, errors.New("no network joint")
	}

	ips := orderListenerIPs(addrs)
	if len(ips) == 0 {
		return nil, errors.New("no usable listener address")
	}

	return ips, nil
}

// orderListenerIPs extracts the IPs from ip:port listener addresses, dropping
// duplicates and anything unparseable.
func orderListenerIPs(addrs []string) []string {
	var loopback, v4, v6 []string
	seen := make(map[string]bool)
	for _, addr := range addrs {
		ip := getIpFromServerString(addr)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true

		parsed := net.ParseIP(ip)
		switch {
		case parsed == nil:
		case parsed.IsLoopback():
			loopback = append(loopback, ip)
		case parsed.To4() != nil:
			v4 = append(v4, ip)
		default:
			v6 = append(v6, ip)
		}
	}

	ips := make([]string, 0, len(loopback)+len(v4)+len(v6))
	ips = append(ips, loopback...)
	ips = append(ips, v4...)
	ips = append(ips, v6...)

	return ips
}

// getIpFromServerString returns ip address from the ip:port
// address pair.
func getIpFromServerString(addrStr string) string {
	if host, _, err := net.SplitHostPort(addrStr); err == nil {
		return host
	}

	return strings.Trim(addrStr, "[]")
}
