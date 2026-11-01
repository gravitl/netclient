package firewall

import (
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/schema"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TestInsertEgressRoutingRulesKeepsEveryVirtualNATRange runs real iptables in a private
// network namespace: two virtual NAT ranges on one egress node share the node's VNAT chains,
// and both ranges must keep their NETMAP and MASQUERADE rules, also after a repeated insert.
func TestInsertEgressRoutingRulesKeepsEveryVirtualNATRange(t *testing.T) {
	enterPrivateNetNamespace(t)
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables binary not found")
	}

	h, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "vnatlan0"}}
	if err := h.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	if err := h.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	for _, cidr := range []string{"10.0.5.1/24", "10.0.7.1/24"} {
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.AddrAdd(link, addr); err != nil {
			t.Fatal(err)
		}
	}

	ipv4Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		t.Fatal(err)
	}
	ipv6Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		t.Fatal(err)
	}
	manager := &iptablesManager{
		ipv4Client:   ipv4Client,
		ipv6Client:   ipv6Client,
		ingRules:     make(serverrulestable),
		engressRules: make(serverrulestable),
		aclRules:     make(serverrulestable),
	}
	if !manager.checkNETMAPSupport(true) {
		t.Skip("iptables NETMAP target not available")
	}

	const egressNodeID = "0123abcd-vnat-multi-range-test"
	ranges := []struct{ real, virtual string }{
		{real: "10.0.5.182/32", virtual: "198.19.229.175/32"},
		{real: "10.0.7.253/32", virtual: "198.19.231.240/32"},
	}
	egressInfo := models.EgressInfo{EgressID: egressNodeID}
	for _, r := range ranges {
		egressInfo.EgressGWCfg.RangesWithMetric = append(egressInfo.EgressGWCfg.RangesWithMetric, models.EgressRangeMetric{
			Network:        r.real,
			VirtualNetwork: r.virtual,
			Nat:            true,
			Mode:           schema.VirtualNAT,
		})
	}

	preroutingChain, postroutingChain := getVNATChainNames(egressNodeID)
	for insert := 1; insert <= 2; insert++ {
		if err := manager.InsertEgressRoutingRules("vnat-test-server", egressInfo); err != nil {
			t.Fatalf("insert %d: %v", insert, err)
		}
		prerouting := listChainRules(t, ipv4Client, preroutingChain)
		postrouting := listChainRules(t, ipv4Client, postroutingChain)
		if len(prerouting) != len(ranges) || len(postrouting) != len(ranges) {
			t.Fatalf("insert %d: want %d rules per VNAT chain, got\n%s:\n%s\n%s:\n%s", insert, len(ranges),
				preroutingChain, strings.Join(prerouting, "\n"), postroutingChain, strings.Join(postrouting, "\n"))
		}
		for _, r := range ranges {
			if !anyRuleContains(prerouting, "-d "+r.virtual, "-j NETMAP", "--to "+r.real) {
				t.Errorf("insert %d: no NETMAP %s -> %s in %s:\n%s", insert, r.virtual, r.real, preroutingChain, strings.Join(prerouting, "\n"))
			}
			if !anyRuleContains(postrouting, "-o vnatlan0", "-d "+r.real, "-j MASQUERADE") {
				t.Errorf("insert %d: no MASQUERADE to %s in %s:\n%s", insert, r.real, postroutingChain, strings.Join(postrouting, "\n"))
			}
		}
		for chain, jump := range map[string]string{"PREROUTING": preroutingChain, "POSTROUTING": postroutingChain} {
			if n := countRulesContaining(listChainRules(t, ipv4Client, chain), "-j "+jump); n != 1 {
				t.Errorf("insert %d: want 1 jump to %s in %s, got %d", insert, jump, chain, n)
			}
		}
	}
}

// enterPrivateNetNamespace moves the test goroutine onto a locked thread in a fresh network
// namespace. Netlink sockets and the iptables processes forked from this goroutine inherit it;
// the thread is never unlocked, so it exits with the test and the namespace goes with it.
func enterPrivateNetNamespace(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skip("needs CAP_SYS_ADMIN to create a network namespace")
		}
		t.Fatal(err)
	}
}

func listChainRules(t *testing.T, client *iptables.IPTables, chain string) []string {
	t.Helper()
	lines, err := client.List(defaultNatTable, chain)
	if err != nil {
		t.Fatal(err)
	}
	var rules []string
	for _, line := range lines {
		if strings.HasPrefix(line, "-A ") {
			rules = append(rules, line)
		}
	}
	return rules
}

func anyRuleContains(rules []string, parts ...string) bool {
	for _, rule := range rules {
		if containsAll(rule, parts) {
			return true
		}
	}
	return false
}

func countRulesContaining(rules []string, part string) int {
	n := 0
	for _, rule := range rules {
		if strings.Contains(rule, part) {
			n++
		}
	}
	return n
}

func containsAll(s string, parts []string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
