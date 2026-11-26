package firewall

import (
	"bytes"
	"net"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestAddJumpRulesEncodesMetricsPortInNetworkByteOrder(t *testing.T) {
	const (
		serverName  = "metrics-port-byte-order-test"
		metricsPort = 0x1234
	)

	previousServer := config.GetServer(serverName)
	previousCurrServer := config.CurrServer
	config.UpdateServer(serverName, config.Server{
		ServerConfig: models.ServerConfig{MetricsPort: metricsPort},
	})
	config.CurrServer = serverName
	t.Cleanup(func() {
		config.CurrServer = previousCurrServer
		if previousServer == nil {
			config.DeleteServer(serverName)
			return
		}
		config.UpdateServer(serverName, *previousServer)
	})

	var requests []netlink.Message
	conn, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		requests = append(requests, req...)
		return req, nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	(&nftablesManager{conn: conn}).addJumpRules()
	expectedCmp, err := expr.Marshal(byte(nftables.TableFamilyINet), &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     []byte{0x12, 0x34},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range requests {
		if bytes.Contains(req.Data, []byte(aclInputRulesChain+"\x00")) && bytes.Contains(req.Data, expectedCmp) {
			return
		}
	}
	t.Fatalf("metrics port %d was not encoded in network byte order in %s", metricsPort, aclInputRulesChain)
}

// TestUpsertAclRuleKeepsEveryIPv6Destination checks that an ACL with several
// IPv6 destinations keeps a rule for each of them.
func TestUpsertAclRuleKeepsEveryIPv6Destination(t *testing.T) {
	conn, err := nftables.New(nftables.WithTestDial(ipv6DstTestDial))
	if err != nil {
		t.Fatal(err)
	}
	manager := &nftablesManager{
		conn:         conn,
		ingRules:     make(serverrulestable),
		engressRules: make(serverrulestable),
		aclRules:     make(serverrulestable),
	}

	manager.UpsertAclRule("server", models.AclRule{
		ID:      "acl",
		IP6List: []net.IPNet{cidr(t, "2001:db8::2/128")},
		Dst6:    []net.IPNet{cidr(t, "2001:db8::1/128"), cidr(t, "2001:db8::3/128")},
		Allowed: true,
	})

	rules := manager.aclRules["server"]["acl"].rulesMap["acl"]
	if len(rules) != 2 {
		t.Fatalf("%s has %d rules after UpsertAclRule with two destinations, want 2", aclInputRulesChain, len(rules))
	}
	if genRuleKey(rules[0].rule...) == genRuleKey(rules[1].rule...) {
		t.Fatalf("both destinations use rule key %q", genRuleKey(rules[0].rule...))
	}
}

func cidr(t *testing.T, s string) net.IPNet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return *ipNet
}

// ipv6DstTestDial answers a rule batch the way the kernel does: a rule create that
// asks for an echo (newer google/nftables sets NLM_F_ECHO) gets its message back
// with a rule handle, then the first message of the batch is acknowledged. A
// receive with nothing pending gets a bare acknowledgement, which is what older
// library versions read once per message.
func ipv6DstTestDial(req []netlink.Message) ([]netlink.Message, error) {
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
			Data: binaryutil.BigEndian.PutUint64(uint64(m.Header.Sequence)),
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
