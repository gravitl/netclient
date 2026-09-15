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
	lo, hi := parsePortRange("80-90")
	if lo != 80 || hi != 90 {
		t.Fatalf("got %d-%d", lo, hi)
	}
	lo, hi = parsePortRange("443")
	if lo != 443 || hi != 0 {
		t.Fatalf("got %d-%d", lo, hi)
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
