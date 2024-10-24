package dns

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/miekg/dns"
)

var dnsSyncMutex = sync.Mutex{} // used to mutex functions of the DNS

type dnsRecord struct {
	Name string
	// Type of record, 1 for A, 5 for CNAME, 28 for AAAA
	Type  uint16
	RData string
}

// new a dnsRecord object
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

// Sync up the DNS entries with NM server
func SyncDNS(network string, dnsEntries []models.DNSEntry) error {
	dnsSyncMutex.Lock()
	defer dnsSyncMutex.Unlock()
	if len(dnsEntries) == 0 {
		return errors.New("no DNS entry")
	}

	defaultDomain := config.GetServer(config.CurrServer).DefaultDomain

	dnsEntryMap := []dnsRecord{}

	for _, v := range dnsEntries {

		if !strings.HasSuffix(v.Name, v.Network) {
			if !strings.HasSuffix(v.Name, defaultDomain) {
				continue
			}
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
