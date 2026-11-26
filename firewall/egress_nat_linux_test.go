package firewall

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/nftables"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// TestInsertEgressRoutingRulesSkipsLoopbackNATRange checks that a NAT egress range that is an
// address of this host gets no MASQUERADE on lo but keeps its destination-side SNAT, while a
// range behind another interface keeps its MASQUERADE.
func TestInsertEgressRoutingRulesSkipsLoopbackNATRange(t *testing.T) {
	const server, hostRange, lanRange = "loopback-nat-range-test", "127.0.0.1/32", "198.51.100.50/32"
	egressInfo := models.EgressInfo{EgressID: server, Network: config.ToIPNet("203.0.113.0/24"),
		EgressGwAddr: config.ToIPNet("203.0.113.1/32")}
	egressInfo.EgressGWCfg.RangesWithMetric = []models.EgressRangeMetric{
		{Network: hostRange, Nat: true}, {Network: lanRange, Nat: true}}
	lanIface, err := getInterfaceName(config.ToIPNet(lanRange))
	if err != nil {
		t.Skipf("loopback NAT needs a route to %s: %v", lanRange, err)
	}
	// Stub iptables binary: only the output of --version matters, every other command just exits 0.
	fakeIptables := filepath.Join(t.TempDir(), "iptables")
	if err := os.WriteFile(fakeIptables, []byte("#!/bin/sh\n[ \"$1\" = --version ] && echo 'iptables v1.8.10 (legacy)'\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ipt, err := iptables.New(iptables.Path(fakeIptables))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := nftables.New(nftables.WithTestDial(loopbackNATTestDial))
	if err != nil {
		t.Fatal(err)
	}
	for backend, manager := range map[string]firewallController{
		"iptables": &iptablesManager{ipv4Client: ipt, engressRules: make(serverrulestable)},
		"nftables": &nftablesManager{conn: conn, engressRules: make(serverrulestable)},
	} {
		if err := manager.InsertEgressRoutingRules(server, egressInfo); err != nil {
			t.Fatal(err)
		}
		assertEgressRangeRules(t, backend, manager.FetchRuleTable(server, egressTable)[server].rulesMap[server], lanIface)
	}
}

// assertEgressRangeRules checks that no MASQUERADE leaves via lo, that the host range keeps its
// destination-side SNAT and that the range behind another interface still gets its MASQUERADE.
func assertEgressRangeRules(t *testing.T, backend string, rules []ruleInfo, lanIface string) {
	t.Helper()
	all := ""
	for _, rule := range rules {
		line := strings.Join(rule.rule, " ")
		all += line + "\n"
		if strings.Contains(line, "-o lo ") {
			t.Errorf("%s: MASQUERADE on lo: %s", backend, line)
		}
	}
	if !strings.Contains(all, "-s 127.0.0.1/32 -o netmaker -j MASQUERADE") {
		t.Errorf("%s: no destination-side MASQUERADE for the host range: %v", backend, rules)
	}
	if !strings.Contains(all, "-o "+lanIface+" -j MASQUERADE") {
		t.Errorf("%s: no MASQUERADE for the range via %s: %v", backend, lanIface, rules)
	}
}

// loopbackNATTestDial answers a rule batch the way the kernel does: a rule create that
// asks for an echo (newer google/nftables sets NLM_F_ECHO) gets its message back
// with a rule handle, then the first message of the batch is acknowledged. A
// receive with nothing pending gets a bare acknowledgement, which is what older
// library versions read once per message.
func loopbackNATTestDial(req []netlink.Message) ([]netlink.Message, error) {
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
