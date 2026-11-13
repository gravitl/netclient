package firewall

import (
	"bytes"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/gravitl/netmaker/models"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// TestAclRuleSurvivesSharedMatch covers ACL changes where another ACL ID produces the
// same match: the ACL that is still there must keep its nftables rule.
func TestAclRuleSurvivesSharedMatch(t *testing.T) {
	const server = "acl-shared-match-test"
	rule := func(id string) models.AclRule {
		return models.AclRule{
			ID:              id,
			IPList:          []net.IPNet{mustCIDR(t, "100.64.0.2/32")},
			Dst:             []net.IPNet{mustCIDR(t, "100.64.0.1/32")},
			AllowedProtocol: models.TCP,
			AllowedPorts:    []string{"22"},
			Allowed:         true,
		}
	}

	t.Run("acl id replaced", func(t *testing.T) {
		n := newFakeNftablesManager(t)
		ProcessAclRules(server, &models.FwUpdate{AclRules: map[string]models.AclRule{"acl-old": rule("acl-old")}})
		ProcessAclRules(server, &models.FwUpdate{AclRules: map[string]models.AclRule{"acl-new": rule("acl-new")}})
		if got := countAclRules(t, n, aclInputRulesChain); got != 1 {
			t.Fatalf("%s has %d ACL rules after the ACL ID changed, want 1", aclInputRulesChain, got)
		}
	})

	t.Run("sibling acl deleted", func(t *testing.T) {
		n := newFakeNftablesManager(t)
		ProcessAclRules(server, &models.FwUpdate{AclRules: map[string]models.AclRule{
			"acl-a": rule("acl-a"),
			"acl-b": rule("acl-b"),
		}})
		if got := countAclRules(t, n, aclInputRulesChain); got != 2 {
			t.Fatalf("%s has %d ACL rules for two ACLs with the same match, want 2", aclInputRulesChain, got)
		}
		ProcessAclRules(server, &models.FwUpdate{AclRules: map[string]models.AclRule{"acl-b": rule("acl-b")}})
		if got := countAclRules(t, n, aclInputRulesChain); got != 1 {
			t.Fatalf("%s has %d ACL rules after deleting a sibling ACL, want 1", aclInputRulesChain, got)
		}
	})

	t.Run("egress acl id replaced", func(t *testing.T) {
		n := newFakeNftablesManager(t)
		egress := func(id string) map[string]models.EgressInfo {
			return map[string]models.EgressInfo{"egress": {
				EgressID:      "egress",
				EgressFwRules: map[string]models.AclRule{id: rule(id)},
			}}
		}
		processEgressFwRules(server, egress("acl-old"))
		processEgressFwRules(server, egress("acl-new"))
		if got := countAclRules(t, n, aclFwdRulesChain); got != 1 {
			t.Fatalf("%s has %d ACL rules after the ACL ID changed, want 1", aclFwdRulesChain, got)
		}
	})
}

// newFakeNftablesManager installs, as fwCrtl, an nftablesManager whose connection talks
// to an in-memory rule list instead of the kernel, so the test needs no privileges.
func newFakeNftablesManager(t *testing.T) *nftablesManager {
	t.Helper()
	ruleset := &fakeRuleset{}
	conn, err := nftables.New(nftables.WithTestDial(ruleset.handle))
	if err != nil {
		t.Fatal(err)
	}
	n := &nftablesManager{
		conn:         conn,
		ingRules:     make(serverrulestable),
		engressRules: make(serverrulestable),
		aclRules:     make(serverrulestable),
	}
	previous := fwCrtl
	fwCrtl = n
	t.Cleanup(func() { fwCrtl = previous })
	return n
}

var (
	newRuleMsgType = netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWRULE)
	getRuleMsgType = netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETRULE)
	delRuleMsgType = netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_DELRULE)
)

// fakeRuleset keeps added rules as the messages the kernel would dump for them. It
// handles rule add, dump and delete by handle, and accepts every other request.
type fakeRuleset struct {
	lastHandle uint64
	rules      []netlink.Message
}

func (f *fakeRuleset) handle(reqs []netlink.Message) ([]netlink.Message, error) {
	var replies []netlink.Message
	for _, req := range reqs {
		switch req.Header.Type {
		case newRuleMsgType:
			f.lastHandle++
			handle, err := netlink.MarshalAttributes([]netlink.Attribute{
				{Type: unix.NFTA_RULE_HANDLE, Data: binaryutil.BigEndian.PutUint64(f.lastHandle)},
			})
			if err != nil {
				return nil, err
			}
			data := append(slices.Clone(req.Data), handle...)
			f.rules = append(f.rules, netlink.Message{Header: netlink.Header{Type: newRuleMsgType}, Data: data})
		case delRuleMsgType:
			handle := ruleMsgAttr(req, unix.NFTA_RULE_HANDLE)
			f.rules = slices.DeleteFunc(f.rules, func(m netlink.Message) bool {
				return bytes.Equal(ruleMsgAttr(m, unix.NFTA_RULE_HANDLE), handle)
			})
		case getRuleMsgType:
			chain := ruleMsgAttr(req, unix.NFTA_RULE_CHAIN)
			for _, m := range f.rules {
				if bytes.Equal(ruleMsgAttr(m, unix.NFTA_RULE_CHAIN), chain) {
					replies = append(replies, m)
				}
			}
		}
	}
	return replies, nil
}

func ruleMsgAttr(m netlink.Message, attrType uint16) []byte {
	ad, err := netlink.NewAttributeDecoder(m.Data[4:])
	if err != nil {
		return nil
	}
	for ad.Next() {
		if ad.Type() == attrType {
			return ad.Bytes()
		}
	}
	return nil
}

func countAclRules(t *testing.T, n *nftablesManager, chain string) int {
	t.Helper()
	rules, err := n.conn.GetRules(filterTable, &nftables.Chain{Name: chain, Table: filterTable})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, rule := range rules {
		if strings.HasPrefix(string(rule.UserData), "-s:") {
			count++
		}
	}
	return count
}

func mustCIDR(t *testing.T, cidr string) net.IPNet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return *ipNet
}
