package dns

import (
	"net"
	"reflect"
	"testing"

	"github.com/gravitl/netmaker/models"
	"github.com/miekg/dns"
)

func TestDomainMatchesPattern(t *testing.T) {
	tests := []struct {
		query   string
		pattern string
		want    bool
	}{
		{"github.com", "github.com", true},
		{"api.github.com", "github.com", true},
		{"github.com", "*.github.com", true},
		{"api.github.com", "*.github.com", true},
		{"notgithub.com", "github.com", false},
		{"foo.intercom.io", "*.intercom.io", true},
		{"intercom.io", "*.intercom.io", true},
	}
	for _, tc := range tests {
		if got := domainMatchesPattern(tc.query, tc.pattern); got != tc.want {
			t.Fatalf("domainMatchesPattern(%q, %q) = %v, want %v", tc.query, tc.pattern, got, tc.want)
		}
	}
}

func TestMatchesEgressDomain(t *testing.T) {
	SyncEgressDomainPatterns(nil)
	if MatchesEgressDomain("github.com") {
		t.Fatal("expected no match with empty patterns")
	}

	SyncEgressDomainPatterns([]models.EgressDomain{{Domain: "github.com"}})
	if !MatchesEgressDomain("github.com.") {
		t.Fatal("expected match for github.com")
	}
	if !MatchesEgressDomain("api.github.com") {
		t.Fatal("expected match for api.github.com")
	}
}

func TestEgressResolutionServersFrom(t *testing.T) {
	public := []string{"8.8.8.8", "1.1.1.1"}

	tests := []struct {
		name        string
		domain      string
		nameservers []models.Nameserver
		want        []string
	}{
		{
			name:        "empty nameservers uses public fallback",
			domain:      "github.com",
			nameservers: nil,
			want:        public,
		},
		{
			name:   "domain-specific nameserver does not match unrelated domain",
			domain: "github.com",
			nameservers: []models.Nameserver{
				{IPs: []string{"10.0.0.53"}, MatchDomain: "corp.local"},
			},
			want: public,
		},
		{
			name:   "domain-specific nameserver matches hostname",
			domain: "host.corp.local",
			nameservers: []models.Nameserver{
				{IPs: []string{"10.0.0.53"}, MatchDomain: "corp.local"},
			},
			want: []string{"10.0.0.53"},
		},
		{
			name:   "catch-all nameserver matches any domain",
			domain: "github.com",
			nameservers: []models.Nameserver{
				{IPs: []string{"10.0.0.1"}, MatchDomain: "."},
			},
			want: []string{"10.0.0.1"},
		},
		{
			name:   "non-fallback nameservers come before fallback",
			domain: "host.corp.local",
			nameservers: []models.Nameserver{
				{IPs: []string{"10.0.0.2"}, MatchDomain: "corp.local", IsFallback: true},
				{IPs: []string{"10.0.0.1"}, MatchDomain: "corp.local"},
			},
			want: []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			name:   "matching nameserver with empty IPs uses public fallback",
			domain: "host.corp.local",
			nameservers: []models.Nameserver{
				{IPs: []string{}, MatchDomain: "corp.local"},
			},
			want: public,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := egressResolutionServersFrom(tc.domain, tc.nameservers)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("egressResolutionServersFrom(%q, ...) = %v, want %v", tc.domain, got, tc.want)
			}
		})
	}
}

func TestFormatDNSServerAddr(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"8.8.8.8", "8.8.8.8:53"},
		{"2001:4860:4860::8888", "[2001:4860:4860::8888]:53"},
		{"[2001:4860:4860::8888]", "[2001:4860:4860::8888]:53"},
	}
	for _, tc := range tests {
		if got := formatDNSServerAddr(tc.ip); got != tc.want {
			t.Fatalf("formatDNSServerAddr(%q) = %q, want %q", tc.ip, got, tc.want)
		}
	}
}

func TestLimitEgressIPs(t *testing.T) {
	manyIPs := []net.IP{
		net.ParseIP("1.0.0.1"),
		net.ParseIP("1.0.0.2"),
		net.ParseIP("1.0.0.3"),
		net.ParseIP("1.0.0.4"),
		net.ParseIP("1.0.0.5"),
		net.ParseIP("1.0.0.6"),
	}

	got := limitEgressIPs(manyIPs)
	if len(got) != egressMaxResolvedIPs {
		t.Fatalf("limitEgressIPs returned %d IPs, want %d", len(got), egressMaxResolvedIPs)
	}
	if got[0].String() != "1.0.0.1" || got[3].String() != "1.0.0.4" {
		t.Fatalf("limitEgressIPs kept unexpected IPs: %v", got)
	}

	dupIPs := []net.IP{
		net.ParseIP("1.0.0.1"),
		net.ParseIP("1.0.0.1"),
		net.ParseIP("1.0.0.2"),
	}
	got = limitEgressIPs(dupIPs)
	if len(got) != 2 {
		t.Fatalf("limitEgressIPs deduped count = %d, want 2", len(got))
	}
}

func TestLimitEgressDNSAnswers(t *testing.T) {
	answers := make([]dns.RR, 0, 6)
	for i := 1; i <= 6; i++ {
		answers = append(answers, &dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(1, 0, 0, byte(i)),
		})
	}

	got := limitEgressDNSAnswers(answers)
	if len(got) != egressMaxResolvedIPs {
		t.Fatalf("limitEgressDNSAnswers returned %d answers, want %d", len(got), egressMaxResolvedIPs)
	}

	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
		Target: "cdn.example.com.",
	}
	answers = append([]dns.RR{cname}, answers...)
	got = limitEgressDNSAnswers(answers)
	if len(got) != egressMaxResolvedIPs+1 {
		t.Fatalf("limitEgressDNSAnswers returned %d answers, want %d", len(got), egressMaxResolvedIPs+1)
	}
	if _, ok := got[0].(*dns.CNAME); !ok {
		t.Fatal("expected CNAME record to be preserved")
	}
}
