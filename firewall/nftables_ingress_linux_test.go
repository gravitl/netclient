package firewall

import (
	"net"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/gravitl/netmaker/models"
	"github.com/mdlayher/netlink"
)

func TestInsertIngressRoutingRulesAppliesCIDRMask(t *testing.T) {
	tests := []struct {
		name       string
		src, dst   string
		srcMaskLen int
		dstMaskLen int
	}{
		{name: "IPv4 network", src: "198.51.100.0/24", dst: "192.0.2.0/24", srcMaskLen: 24, dstMaskLen: 24},
		{name: "IPv4 host", src: "198.51.100.10/32", dst: "192.0.2.20/32", srcMaskLen: 32, dstMaskLen: 32},
		{name: "IPv6 network", src: "2001:db8:1::/64", dst: "2001:db8:2::/64", srcMaskLen: 64, dstMaskLen: 64},
		{name: "IPv6 host", src: "2001:db8:1::10/128", dst: "2001:db8:2::20/128", srcMaskLen: 128, dstMaskLen: 128},
		{name: "IPv4 any destination", src: "198.51.100.10/32", srcMaskLen: 32},
		{name: "IPv6 any destination", src: "2001:db8:1::10/128", srcMaskLen: 128},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rule := insertIngressRuleForTest(t, test.src, test.dst)
			if test.dst == "" {
				assertNoDestinationMatch(t, rule, test.src)
			}
			if got := maskPrefixLen(t, rule, 1); got != test.srcMaskLen {
				t.Errorf("source mask prefix = %d, want %d", got, test.srcMaskLen)
			}
			if test.dst == "" {
				return
			}
			if got := maskPrefixLen(t, rule, 4); got != test.dstMaskLen {
				t.Errorf("destination mask prefix = %d, want %d", got, test.dstMaskLen)
			}
		})
	}
}

func insertIngressRuleForTest(t *testing.T, srcCIDR, dstCIDR string) *nftables.Rule {
	t.Helper()
	conn, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 1 && req[0].Header.Flags&netlink.Dump != 0 {
			return nil, nil
		}
		return []netlink.Message{{
			Header: netlink.Header{Type: netlink.Error},
			Data:   []byte{0, 0, 0, 0},
		}}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	_, srcNet, err := net.ParseCIDR(srcCIDR)
	if err != nil {
		t.Fatal(err)
	}
	dstNet := &net.IPNet{}
	if dstCIDR != "" {
		_, dstNet, err = net.ParseCIDR(dstCIDR)
		if err != nil {
			t.Fatal(err)
		}
	}

	n := &nftablesManager{
		conn:         conn,
		ingRules:     make(serverrulestable),
		engressRules: make(serverrulestable),
		aclRules:     make(serverrulestable),
	}
	if err := n.InsertIngressRoutingRules("server", models.IngressInfo{
		IngressID: "ingress",
		Rules: []models.FwRule{{
			SrcIP: *srcNet,
			DstIP: *dstNet,
			Allow: true,
		}},
	}); err != nil {
		t.Fatalf("InsertIngressRoutingRules: %v", err)
	}

	rules := n.ingRules["server"]["ingress"].rulesMap[staticNodeRules]
	if len(rules) != 1 {
		t.Fatalf("saved ingress rules = %d, want 1", len(rules))
	}
	return rules[0].nfRule.(*nftables.Rule)
}

func maskPrefixLen(t *testing.T, rule *nftables.Rule, index int) int {
	t.Helper()
	if index >= len(rule.Exprs) {
		t.Fatalf("rule has %d expressions, want a mask at index %d", len(rule.Exprs), index)
	}
	bitwise, ok := rule.Exprs[index].(*expr.Bitwise)
	if !ok {
		t.Fatalf("rule expression %d is %T, want *expr.Bitwise applying the CIDR mask", index, rule.Exprs[index])
	}
	ones, bits := net.IPMask(bitwise.Mask).Size()
	if bits == 0 {
		return -1
	}
	return ones
}

// assertNoDestinationMatch checks that the rule reads nothing from the network
// header except the source address of srcCIDR's family: 4 bytes at offset 12
// in IPv4, 16 bytes at offset 8 in IPv6.
func assertNoDestinationMatch(t *testing.T, rule *nftables.Rule, srcCIDR string) {
	t.Helper()
	srcIP, _, err := net.ParseCIDR(srcCIDR)
	if err != nil {
		t.Fatal(err)
	}
	srcOffset, srcLen := uint32(8), uint32(16)
	if srcIP.To4() != nil {
		srcOffset, srcLen = 12, 4
	}
	for i, e := range rule.Exprs {
		payload, ok := e.(*expr.Payload)
		if !ok || payload.Base != expr.PayloadBaseNetworkHeader {
			continue
		}
		if payload.Offset != srcOffset || payload.Len != srcLen {
			t.Errorf("rule expression %d loads %d bytes at network header offset %d, want only the source address", i, payload.Len, payload.Offset)
		}
	}
}
