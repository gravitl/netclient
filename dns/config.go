package dns

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/gravitl/netclient/config"
	dnsconfig "github.com/gravitl/netclient/dns/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
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
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if _, ok := nameserverIPsMap[ip]; !ok {
			dnsConfig.Nameservers = append(dnsConfig.Nameservers, parsed)
			nameserverIPsMap[ip] = true
		}
	}

	// Exit node (CurrGw) or match-all nameservers → system-wide DNS
	// (networksetup on macOS). Otherwise split DNS via /etc/resolver.
	nc := config.Netclient()
	if matchAllDomains || (nc != nil && (len(nc.CurrGwNmIP) > 0 || len(nc.CurrGwNmIP6) > 0)) {
		dnsConfig.SplitDNS = false
	}

	if len(dnsConfig.Nameservers) == 0 {
		return errors.New("no nameservers to configure")
	}

	if configManager == nil {
		return errors.New("dns config manager not initialized")
	}

	logger.Log(0, "applying dns:", fmt.Sprintf("split=%v match_all=%v curr_gw=%v nameservers=%v",
		dnsConfig.SplitDNS, matchAllDomains, nc != nil && (len(nc.CurrGwNmIP) > 0 || len(nc.CurrGwNmIP6) > 0),
		dnsConfig.Nameservers))

	return configManager.Configure(ncutils.GetInterfaceName(), dnsConfig)
}

// getDnsIps returns listener addresses to publish as OS nameservers.
//
// On non-macOS, every bind is published (IPv4 then IPv6) so dual-stack hosts
// are not left with an unreachable IPv6-only nameserver.
//
// On macOS we only publish the loopback listener (127.51.8.21). Overlay WG
// addresses keep working only while the tunnel is up and cause DNS breakage
// after exit-node / disconnect; loopback answers regardless of tunnel state.
func getDnsIps() ([]string, error) {
	addrs := GetDNSServerInstance().AddrList
	if len(addrs) == 0 {
		return nil, errors.New("no listener is running")
	}

	if len(config.GetNodes()) == 0 {
		return nil, errors.New("no network joint")
	}

	ips := orderListenerIPs(addrs)
	ips = nameserversForOS(ips)
	if len(ips) == 0 {
		return nil, errors.New("no usable listener address")
	}

	return ips, nil
}

// nameserversForOS filters listener IPs for OS DNS installation.
// Darwin: loopback only when available; other platforms: unchanged.
func nameserversForOS(ips []string) []string {
	if runtime.GOOS != "darwin" {
		return ips
	}
	var loopback []string
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil && parsed.IsLoopback() {
			loopback = append(loopback, ip)
		}
	}
	if len(loopback) > 0 {
		return loopback
	}
	return ips
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
