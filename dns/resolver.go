package dns

import (
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"golang.org/x/exp/slog"
)

var dnsMapMutex = sync.Mutex{} // used to mutex functions of the DNS

type DNSResolver struct {
	//dnsEntriesCacheMap   map[string]DNSRecord
	DnsEntriesCacheStore map[string]dns.RR
}

var DnsResolver *DNSResolver

func init() {
	DnsResolver = &DNSResolver{}
}

// GetInstance
func GetDNSResolverInstance() *DNSResolver {
	return DnsResolver
}

// ServeDNS handles a DNS request
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	slog.Info("receiving DNS query request", "Info", r.Question[0])
	reply := &dns.Msg{}
	reply.SetReply(r)
	reply.RecursionAvailable = true
	reply.Rcode = dns.RcodeSuccess

	resp := GetDNSResolverInstance().Lookup(r)
	if resp != nil {
		reply.Answer = append(reply.Answer, resp)
	} else {
		reply.Rcode = dns.RcodeNameError
	}

	err := w.WriteMsg(reply)
	if err != nil {
		slog.Error("write DNS response message error: ", "error", err.Error())
	}
}

func (d *DNSResolver) RegisterA(record dnsRecord) error {
	dnsMapMutex.Lock()
	defer dnsMapMutex.Unlock()

	r := new(dns.A)
	r.Hdr = dns.RR_Header{Name: dns.Fqdn(record.Name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}
	r.A = net.ParseIP(record.RData)

	d.DnsEntriesCacheStore[buildDNSEntryKey(record.Name, record.Type)] = r

	slog.Info("registering A record successfully", "Info", d.DnsEntriesCacheStore[buildDNSEntryKey(record.Name, record.Type)])

	return nil
}

func (d *DNSResolver) RegisterAAAA(record dnsRecord) error {
	dnsMapMutex.Lock()
	defer dnsMapMutex.Unlock()

	r := new(dns.AAAA)
	r.Hdr = dns.RR_Header{Name: record.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}
	r.AAAA = net.ParseIP(record.RData)

	d.DnsEntriesCacheStore[buildDNSEntryKey(record.Name, record.Type)] = r

	return nil
}

func (d *DNSResolver) Lookup(m *dns.Msg) dns.RR {
	dnsMapMutex.Lock()
	defer dnsMapMutex.Unlock()
	q := m.Question[0]
	r, ok := d.DnsEntriesCacheStore[buildDNSEntryKey(strings.TrimSuffix(q.Name, "."), q.Qtype)]
	if !ok {
		return nil
	}

	return r
}
