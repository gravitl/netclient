package firewall

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/nftables"
	"github.com/gravitl/netmaker/models"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// fakeNftRule is a rule held by fakeNftRuleset in place of the kernel.
type fakeNftRule struct {
	table    string
	chain    string
	handle   uint64
	userData string
}

// fakeNftRuleset answers nftables netlink requests like the kernel does for the
// rule operations UpsertAclRule uses: new rules get a handle, dumps list the
// rules of the requested chain and deletes remove the rule with that handle.
type fakeNftRuleset struct {
	t          *testing.T
	rules      []fakeNftRule
	nextHandle uint64
}

func (f *fakeNftRuleset) dial(req []netlink.Message) ([]netlink.Message, error) {
	newRule := netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWRULE)
	delRule := netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_DELRULE)
	if len(req) == 0 {
		return nil, nil
	}
	if len(req) == 1 && req[0].Header.Flags&netlink.Dump != 0 {
		chain := f.attrs(req[0])[unix.NFTA_RULE_CHAIN]
		var reply []netlink.Message
		for _, r := range f.rules {
			if r.chain != chain {
				continue
			}
			handle := make([]byte, 8)
			binary.BigEndian.PutUint64(handle, r.handle)
			data, err := netlink.MarshalAttributes([]netlink.Attribute{
				{Type: unix.NFTA_RULE_TABLE, Data: []byte(r.table + "\x00")},
				{Type: unix.NFTA_RULE_CHAIN, Data: []byte(r.chain + "\x00")},
				{Type: unix.NFTA_RULE_HANDLE, Data: handle},
				{Type: unix.NFTA_RULE_USERDATA, Data: []byte(r.userData)},
			})
			if err != nil {
				f.t.Fatal(err)
			}
			reply = append(reply, netlink.Message{
				Header: netlink.Header{Type: newRule},
				Data:   append(req[0].Data[:4:4], data...),
			})
		}
		return reply, nil
	}
	for _, m := range req {
		switch m.Header.Type {
		case newRule:
			attrs := f.attrs(m)
			f.nextHandle++
			f.rules = append(f.rules, fakeNftRule{
				table:    attrs[unix.NFTA_RULE_TABLE],
				chain:    attrs[unix.NFTA_RULE_CHAIN],
				handle:   f.nextHandle,
				userData: attrs[unix.NFTA_RULE_USERDATA],
			})
		case delRule:
			handle := binary.BigEndian.Uint64([]byte(f.attrs(m)[unix.NFTA_RULE_HANDLE]))
			for i, r := range f.rules {
				if r.handle == handle {
					f.rules = append(f.rules[:i], f.rules[i+1:]...)
					break
				}
			}
		}
	}
	return []netlink.Message{{
		Header: netlink.Header{Type: netlink.Error},
		Data:   []byte{0, 0, 0, 0},
	}}, nil
}

func (f *fakeNftRuleset) attrs(m netlink.Message) map[uint16]string {
	ad, err := netlink.NewAttributeDecoder(m.Data[4:])
	if err != nil {
		f.t.Fatal(err)
	}
	attrs := make(map[uint16]string)
	for ad.Next() {
		attrs[ad.Type()] = string(ad.Bytes())
	}
	if err := ad.Err(); err != nil {
		f.t.Fatal(err)
	}
	for _, name := range []uint16{unix.NFTA_RULE_TABLE, unix.NFTA_RULE_CHAIN} {
		if v, ok := attrs[name]; ok {
			attrs[name] = v[:len(v)-1]
		}
	}
	return attrs
}

func TestUpsertAclRuleKeepsEveryIPv6Destination(t *testing.T) {
	cidr := func(s string) net.IPNet {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		return *ipNet
	}
	tests := []struct {
		name string
		acl  models.AclRule
	}{
		{
			name: "ipv4",
			acl: models.AclRule{
				ID:      "acl-v4",
				IPList:  []net.IPNet{cidr("192.0.2.2/32")},
				Dst:     []net.IPNet{cidr("192.0.2.1/32"), cidr("192.0.2.3/32")},
				Allowed: true,
			},
		},
		{
			name: "ipv6",
			acl: models.AclRule{
				ID:      "acl-v6",
				IP6List: []net.IPNet{cidr("2001:db8::2/128")},
				Dst6:    []net.IPNet{cidr("2001:db8::1/128"), cidr("2001:db8::3/128")},
				Allowed: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleset := &fakeNftRuleset{t: t}
			conn, err := nftables.New(nftables.WithTestDial(ruleset.dial))
			if err != nil {
				t.Fatal(err)
			}
			n := &nftablesManager{
				conn:         conn,
				ingRules:     make(serverrulestable),
				engressRules: make(serverrulestable),
				aclRules:     make(serverrulestable),
			}

			n.UpsertAclRule("server", tt.acl)

			var keys []string
			for _, r := range ruleset.rules {
				if r.chain == aclInputRulesChain {
					keys = append(keys, r.userData)
				}
			}
			if len(keys) != 2 {
				t.Fatalf("%s has %d rules after UpsertAclRule with two destinations, want 2: %q", aclInputRulesChain, len(keys), keys)
			}
			if keys[0] == keys[1] {
				t.Fatalf("both destinations use rule key %q", keys[0])
			}
		})
	}
}
