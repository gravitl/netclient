package firewall

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/gravitl/netmaker/models"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// A rule without a destination matches every destination: it must install as a source-only rule.
func TestInsertIngressRoutingRulesWithoutDestination(t *testing.T) {
	tests := []struct {
		name      string
		src       string
		srcOffset uint32
	}{
		{name: "IPv4", src: "192.0.2.0/24", srcOffset: 12},
		{name: "IPv6", src: "2001:db8:1::/64", srcOffset: 8},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, src, err := net.ParseCIDR(test.src)
			if err != nil {
				t.Fatal(err)
			}
			rule := insertIngressRule(t, models.FwRule{SrcIP: *src, Allow: true})
			for _, ruleExpr := range rule.Exprs {
				switch ruleExpr := ruleExpr.(type) {
				case *expr.Payload:
					if ruleExpr.Offset != test.srcOffset {
						t.Errorf("payload offset = %d, want source offset %d", ruleExpr.Offset, test.srcOffset)
					}
				case *expr.Cmp:
					if len(ruleExpr.Data) == 0 {
						t.Errorf("comparison has no data: %+v", ruleExpr)
					}
				}
			}
			last := rule.Exprs[len(rule.Exprs)-1]
			if verdict, ok := last.(*expr.Verdict); !ok || verdict.Kind != expr.VerdictAccept {
				t.Fatalf("last expression = %#v, want an accept verdict", last)
			}
		})
	}
}

// A destination mask without an address or a destination of another address family cannot match:
// the rule must be skipped, not widened to every destination.
func TestInsertIngressRoutingRulesWithoutDestinationAddress(t *testing.T) {
	tests := []struct {
		name string
		src  string
		dst  net.IPNet
	}{
		{name: "IPv4", src: "192.0.2.0/24", dst: net.IPNet{Mask: net.CIDRMask(32, 32)}},
		{name: "IPv6", src: "2001:db8:1::/64", dst: net.IPNet{Mask: net.CIDRMask(128, 128)}},
		{name: "IPv6 destination on an IPv4 source", src: "192.0.2.0/24", dst: net.IPNet{IP: net.ParseIP("2001:db8::10"), Mask: net.CIDRMask(128, 128)}},
		{name: "IPv4 destination on an IPv6 source", src: "2001:db8:1::/64", dst: net.IPNet{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(32, 32)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, src, err := net.ParseCIDR(test.src)
			if err != nil {
				t.Fatal(err)
			}
			n := newTestManager(t)
			err = n.InsertIngressRoutingRules("server", models.IngressInfo{
				IngressID: "ingress",
				Rules: []models.FwRule{{
					SrcIP: *src,
					DstIP: test.dst,
					Allow: true,
				}},
			})
			if err != nil {
				t.Fatalf("InsertIngressRoutingRules: %v", err)
			}
			if rules := n.ingRules["server"]["ingress"].rulesMap[staticNodeRules]; len(rules) != 0 {
				t.Fatalf("saved ingress rules = %d, want 0", len(rules))
			}
		})
	}
}

// insertIngressRule installs one ingress rule against a test connection.
func insertIngressRule(t *testing.T, rule models.FwRule) *nftables.Rule {
	t.Helper()
	n := newTestManager(t)
	if err := n.InsertIngressRoutingRules("server", models.IngressInfo{
		IngressID: "ingress",
		Rules:     []models.FwRule{rule},
	}); err != nil {
		t.Fatalf("InsertIngressRoutingRules: %v", err)
	}
	rules := n.ingRules["server"]["ingress"].rulesMap[staticNodeRules]
	if len(rules) != 1 {
		t.Fatalf("saved ingress rules = %d, want 1", len(rules))
	}
	return rules[0].nfRule.(*nftables.Rule)
}

// newTestManager builds a manager whose connection answers every non-dump request with success.
func newTestManager(t *testing.T) *nftablesManager {
	t.Helper()
	conn, err := nftables.New(nftables.WithTestDial(noDstTestDial))
	if err != nil {
		t.Fatal(err)
	}
	return &nftablesManager{conn: conn, ingRules: make(serverrulestable)}
}

// noDstTestDial answers a rule batch the way the kernel does: a rule create that
// asks for an echo (newer google/nftables sets NLM_F_ECHO) gets its message back
// with a rule handle, then the first message of the batch is acknowledged. A
// receive with nothing pending gets a bare acknowledgement, which is what older
// library versions read once per message.
func noDstTestDial(req []netlink.Message) ([]netlink.Message, error) {
	if len(req) == 1 && req[0].Header.Flags&netlink.Dump != 0 {
		return nil, nil
	}
	var replies []netlink.Message
	for _, m := range req {
		if m.Header.Flags&netlink.Echo == 0 {
			continue
		}
		handle, err := netlink.MarshalAttributes([]netlink.Attribute{{
			Type: unix.NFTA_RULE_HANDLE,
			Data: binary.BigEndian.AppendUint64(nil, uint64(m.Header.Sequence)),
		}})
		if err != nil {
			return nil, err
		}
		replies = append(replies, netlink.Message{
			Header: netlink.Header{Type: m.Header.Type, Sequence: m.Header.Sequence},
			Data:   append(append([]byte{}, m.Data[:4]...), handle...),
		})
	}
	ack := netlink.Message{Header: netlink.Header{Type: netlink.Error}, Data: []byte{0, 0, 0, 0}}
	if len(req) > 1 {
		ack.Header.Sequence = req[1].Header.Sequence
	}
	return append(replies, ack), nil
}
