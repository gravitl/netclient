package dns

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/gravitl/netmaker/models"
	"github.com/miekg/dns"
)

type dnsRecord struct {
	Name string
	// Type of record, 1 for A, 5 for CNAME, 28 for AAAA
	Type  uint16
	RData string
}

func newDNSRecord(name string, t uint16, dest string) dnsRecord {
	return dnsRecord{
		Name:  name,
		Type:  t,
		RData: dest,
	}
}

func buildDNSEntryKey(name string, t uint16) string {
	return fmt.Sprintf("%s.%d", name, t)
}

func SyncDNS(network string, dnsEntries []models.DNSEntry) error {
	if len(dnsEntries) == 0 {
		return errors.New("no DNS entry")
	}

	dnsEntryMap := []dnsRecord{}

	for _, v := range dnsEntries {

		if !strings.HasSuffix(v.Name, v.Network) {
			continue
		}

		if v.Address != "" {
			if ipv4 := net.ParseIP(v.Address).To4(); ipv4 != nil {
				r := newDNSRecord(v.Name, dns.TypeA, v.Address)
				dnsEntryMap = append(dnsEntryMap, r)
			}
		}

		if v.Address6 != "" {
			if ipv4 := net.ParseIP(v.Address6).To4(); ipv4 == nil {
				r := newDNSRecord(v.Name, dns.TypeAAAA, v.Address6)
				dnsEntryMap = append(dnsEntryMap, r)
			}
		}
	}

	//update the dns records for given network
	GetDNSResolverInstance().DnsEntriesCacheMap[network] = dnsEntryMap

	//Refresh dns store
	GetDNSResolverInstance().DnsEntriesCacheStore = make(map[string]dns.RR)
	for _, v := range GetDNSResolverInstance().DnsEntriesCacheMap {
		for _, d := range v {
			if d.Type == dns.TypeA {
				GetDNSResolverInstance().RegisterA(d)
				continue
			}
			if d.Type == dns.TypeAAAA {
				GetDNSResolverInstance().RegisterAAAA(d)
				continue
			}
		}
	}

	return nil
}
