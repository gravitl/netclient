package firewall

import (
	"net"
	"testing"

	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/schema"
)

func TestWinAclIDHash(t *testing.T) {
	a := winAclIDHash("acl-1")
	b := winAclIDHash("acl-1")
	c := winAclIDHash("acl-2")
	if a != b {
		t.Fatal("expected deterministic hash")
	}
	if a == c {
		t.Fatal("expected different hashes")
	}
}

func TestParsePortRange(t *testing.T) {
	for _, tc := range []struct {
		in     string
		lo, hi uint16
		ok     bool
	}{
		{in: "80-90", lo: 80, hi: 90, ok: true},
		{in: "443", lo: 443, ok: true},
		{in: "80:90", lo: 80, hi: 90, ok: true},
		{in: " 8080 - 8081 ", lo: 8080, hi: 8081, ok: true},
		// Degenerate range collapses to a single-port match.
		{in: "443-443", lo: 443, ok: true},
		// All invalid: a portless spec would allow every port, so these must
		// be rejected rather than coerced to 0.
		{in: "abc", ok: false},
		{in: "8080-abc", ok: false},
		{in: "90-80", ok: false},
		{in: "0", ok: false},
		{in: "0-100", ok: false},
		{in: "70000", ok: false},
		// Empty means "all ports" and is legitimate.
		{in: "", ok: true},
	} {
		lo, hi, ok := parsePortRange(tc.in)
		if ok != tc.ok || lo != tc.lo || hi != tc.hi {
			t.Errorf("parsePortRange(%q) = %d, %d, %v; want %d, %d, %v",
				tc.in, lo, hi, ok, tc.lo, tc.hi, tc.ok)
		}
	}
}

func TestAclToFilterSpecsDropsInvalidPorts(t *testing.T) {
	_, src, _ := net.ParseCIDR("10.0.0.1/32")
	acl := models.AclRule{
		ID:              "rule-c",
		IPList:          []net.IPNet{*src},
		AllowedProtocol: schema.TCP,
		AllowedPorts:    []string{"bogus"},
	}
	if specs := aclToFilterSpecs(acl, aclLayerInbound); len(specs) != 0 {
		t.Fatalf("expected no specs for unparsable port, got %+v", specs)
	}
}

func TestAclToFilterSpecsRange(t *testing.T) {
	_, src, _ := net.ParseCIDR("10.0.0.1/32")
	acl := models.AclRule{
		ID:              "rule-d",
		IPList:          []net.IPNet{*src},
		AllowedProtocol: schema.TCP,
		AllowedPorts:    []string{"8080-8081"},
	}
	specs := aclToFilterSpecs(acl, aclLayerInbound)
	if len(specs) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(specs))
	}
	if specs[0].DstPort != 8080 || specs[0].DstPortMax != 8081 {
		t.Fatalf("unexpected bounds: %+v", specs[0])
	}
}

func TestAclToFilterSpecsInbound(t *testing.T) {
	_, src, _ := net.ParseCIDR("10.0.0.1/32")
	_, dst, _ := net.ParseCIDR("10.0.0.2/32")
	acl := models.AclRule{
		ID:              "rule-a",
		IPList:          []net.IPNet{*src},
		Dst:             []net.IPNet{*dst},
		AllowedProtocol: schema.TCP,
		AllowedPorts:    []string{"443"},
	}
	specs := aclToFilterSpecs(acl, aclLayerInbound)
	if len(specs) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(specs))
	}
	if specs[0].Protocol != aclProtoTCP || specs[0].DstPort != 443 {
		t.Fatalf("unexpected: %+v", specs[0])
	}
}

func TestAclToFilterSpecsForwardDropsPorts(t *testing.T) {
	_, src, _ := net.ParseCIDR("10.0.0.1/32")
	_, dst, _ := net.ParseCIDR("192.168.1.0/24")
	acl := models.AclRule{
		ID:              "rule-b",
		IPList:          []net.IPNet{*src},
		Dst:             []net.IPNet{*dst},
		AllowedProtocol: schema.UDP,
		AllowedPorts:    []string{"53"},
	}
	specs := aclToFilterSpecs(acl, aclLayerForward)
	if len(specs) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(specs))
	}
	if specs[0].DstPort != 0 {
		t.Fatalf("forward layer should ignore ports, got %+v", specs[0])
	}
}
