package firewall

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/nftables"
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

func TestInsertIngressRoutingRulesAppliesCIDRMask(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		dst     string
		maskLen int
	}{
		{name: "IPv4", src: "198.51.100.0/24", dst: "192.0.2.0/24", maskLen: 24},
		{name: "IPv6", src: "2001:db8:1::/64", dst: "2001:db8:2::/64", maskLen: 64},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn, err := nftables.New(nftables.WithTestDial(cidrMaskTestDial))
			if err != nil {
				t.Fatal(err)
			}
			_, srcNet, err := net.ParseCIDR(test.src)
			if err != nil {
				t.Fatal(err)
			}
			_, dstNet, err := net.ParseCIDR(test.dst)
			if err != nil {
				t.Fatal(err)
			}
			n := &nftablesManager{conn: conn, ingRules: make(serverrulestable)}
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
			rule := rules[0].nfRule.(*nftables.Rule)
			for _, index := range []int{1, 4} {
				bitwise, ok := rule.Exprs[index].(*expr.Bitwise)
				if !ok {
					t.Fatalf("rule expression %d is %T, want *expr.Bitwise applying the CIDR mask", index, rule.Exprs[index])
				}
				if ones, _ := net.IPMask(bitwise.Mask).Size(); ones != test.maskLen {
					t.Errorf("rule expression %d mask prefix = %d, want %d", index, ones, test.maskLen)
				}
			}
		})
	}
}

// cidrMaskTestDial answers a rule batch the way the kernel does: a rule create that
// asks for an echo (newer google/nftables sets NLM_F_ECHO) gets its message back
// with a rule handle, then the first message of the batch is acknowledged. A
// receive with nothing pending gets a bare acknowledgement, which is what older
// library versions read once per message.
func cidrMaskTestDial(req []netlink.Message) ([]netlink.Message, error) {
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
