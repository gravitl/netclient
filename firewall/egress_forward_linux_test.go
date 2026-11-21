package firewall

import (
	"bytes"
	"encoding/binary"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

const (
	nftNewRule = netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWRULE)
	nftGetRule = netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETRULE)
	nftDelRule = netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_DELRULE)
)

// egressNftDial is a test dial that hands the rules added through it back to GetRules and records
// the deleted handles.
type egressNftDial struct {
	rules   []netlink.Message
	deleted []uint64
}

func (d *egressNftDial) Dial(req []netlink.Message) ([]netlink.Message, error) {
	var reply []netlink.Message
	for _, msg := range req {
		switch msg.Header.Type {
		case nftNewRule:
			msg.Data = append(msg.Data[:len(msg.Data):len(msg.Data)], nltest.MustMarshalAttributes([]netlink.Attribute{
				{Type: unix.NFTA_RULE_HANDLE, Data: binary.BigEndian.AppendUint64(nil, uint64(len(d.rules)+1))},
			})...)
			d.rules = append(d.rules, msg)
			reply = append(reply, msg)
		case nftGetRule:
			reply = append(reply, d.rules...)
		case nftDelRule:
			ad, _ := netlink.NewAttributeDecoder(msg.Data[4:])
			ad.ByteOrder = binary.BigEndian
			for ad.Next() {
				if ad.Type() == unix.NFTA_RULE_HANDLE {
					d.deleted = append(d.deleted, ad.Uint64())
				}
			}
		default: // echo the batch end, the ack reader does not stop on a rule message type
			reply = append(reply, msg)
		}
	}
	return reply, nil
}

// TestInsertEgressRoutingRulesForwardJumpMatchesEgressRange checks the FORWARD jump into
// NETMAKER-ACL-FWD that an egress installs: one per range, matching the range as the source.
func TestInsertEgressRoutingRulesForwardJumpMatchesEgressRange(t *testing.T) {
	const egressID = "egress-forward-acl-range-test"
	// loopback ranges route in every network namespace, no default route is needed here
	ranges := []string{"127.0.0.10/32", "127.0.0.20/32"}
	var dial egressNftDial
	conn, err := nftables.New(nftables.WithTestDial(dial.Dial))
	if err != nil {
		t.Fatal(err)
	}
	manager := &nftablesManager{conn: conn, engressRules: make(serverrulestable)}
	egressInfo := models.EgressInfo{
		EgressID:     egressID,
		Network:      config.ToIPNet("203.0.113.0/24"),
		EgressGwAddr: config.ToIPNet("203.0.113.1/32"),
	}
	for _, network := range ranges {
		egressInfo.EgressGWCfg.RangesWithMetric = append(egressInfo.EgressGWCfg.RangesWithMetric,
			models.EgressRangeMetric{Network: network, Nat: true})
	}
	if err := manager.InsertEgressRoutingRules(egressID, egressInfo); err != nil {
		t.Fatal(err)
	}

	// the key alone only names the spec, the source has to be in the expressions on the wire
	for _, network := range ranges {
		key := []byte("-s:" + network + ":-i:")
		ip := net.ParseIP(strings.TrimSuffix(network, "/32")).To4()
		jump := func(m netlink.Message) bool {
			return bytes.Contains(m.Data, key) && bytes.Contains(m.Data, ip) && bytes.Contains(m.Data, []byte("-j:"+aclFwdRulesChain))
		}
		if !slices.ContainsFunc(dial.rules, jump) {
			t.Errorf("no FORWARD jump into %s goes out with the source %s", aclFwdRulesChain, network)
		}
	}

	// RemoveRoutingRules drops the table entry, so the jumps are gone from rulesMap either way:
	// the deletes have to name each jump by its key, which carries the range.
	if err := manager.RemoveRoutingRules(egressID, egressTable, egressID); err != nil {
		t.Fatal(err)
	}
	for _, network := range ranges {
		hit := func(h uint64) bool { return bytes.Contains(dial.rules[h-1].Data, []byte("-s:"+network+":-i:")) }
		if !slices.ContainsFunc(dial.deleted, hit) {
			t.Errorf("no FORWARD jump deleted for %s carries the range", network)
		}
	}
}

// TestEgressForwardAclJump checks the jump rule and key both backends share: the range as the
// source, one rule per range and interface, none for repeated or unusable ranges.
func TestEgressForwardAclJump(t *testing.T) {
	const tail = " -o netmaker -j NETMAKER-ACL-FWD -m comment --comment NETMAKER"
	cases := []struct{ network, iface, wantRule, wantKey string }{
		{"198.51.100.10/32", "eth0", "-s 198.51.100.10/32 -i eth0" + tail, "eth0#198.51.100.10/32"},
		{"198.51.100.20/32", "eth0", "-s 198.51.100.20/32 -i eth0" + tail, "eth0#198.51.100.20/32"},
		{"198.51.100.10/32", "eth0", "-s 198.51.100.10/32 -i eth0" + tail, "eth0#198.51.100.10/32"},
		{"2001:db8::10/128", "eth0", "-s 2001:db8::10/128 -i eth0" + tail, "eth0#2001:db8::10/128"},
		{"", "eth0", "", ""},
		{"198.51.100.30/32", "", "", ""},
	}
	for _, tc := range cases {
		spec, key := egressForwardAclJump(config.ToIPNet(tc.network), tc.iface)
		if got := strings.Join(spec, " "); got != tc.wantRule || key != tc.wantKey {
			t.Errorf("%s %s: got rule %q key %q, want %q and %q", tc.iface, tc.network, got, key, tc.wantRule, tc.wantKey)
		}
	}
}
