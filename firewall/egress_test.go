package firewall

import (
	"net"
	"reflect"
	"testing"

	"github.com/gravitl/netmaker/models"
)

// fakeEgressController keeps the egress rule table in memory and records the calls.
type fakeEgressController struct {
	firewallController
	table ruletable
	calls []string
}

func (f *fakeEgressController) FetchRuleTable(string, string) ruletable { return f.table }

func (f *fakeEgressController) RemoveRoutingRules(_, _, key string) error {
	f.calls = append(f.calls, "RemoveRoutingRules "+key)
	delete(f.table, key)
	return nil
}

// the rule map is stored as it comes, which keeps it nil for an egress without rules
func (f *fakeEgressController) AddAclEgressRules(_ string, egressInfo models.EgressInfo) {
	egressID := "acl#" + egressInfo.EgressID
	f.calls = append(f.calls, "AddAclEgressRules "+egressID)
	f.table[egressID] = rulesCfg{extraInfo: egressInfo.EgressFwRules}
}

func (f *fakeEgressController) DeleteAllAclEgressRules(_, egressID string) {
	f.calls = append(f.calls, "DeleteAllAclEgressRules "+egressID)
	delete(f.table, egressID)
}

func testNet(s string) net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return *n
}

func egressUpdate(port, src6, dst6 string) map[string]models.EgressInfo {
	return map[string]models.EgressInfo{
		"egress-1": {
			EgressID:    "egress-1",
			EgressGWCfg: models.EgressGatewayRequest{RangesWithMetric: []models.EgressRangeMetric{{Network: "192.0.2.0/24", Nat: true}}},
			EgressFwRules: map[string]models.AclRule{
				"acl-1": {ID: "acl-1", IPList: []net.IPNet{testNet("198.51.100.7/32")}, IP6List: []net.IPNet{testNet(src6)}, Dst: []net.IPNet{testNet("192.0.2.10/32")}, Dst6: []net.IPNet{testNet(dst6)}, AllowedPorts: []string{port}, Allowed: true},
			},
		},
	}
}

// An update that changes nothing must leave the egress ACL rules alone: removing and
// re-adding them leaves a window in which new forwarded connections hit the chain's drop
// rule. Any change reinstalls every entry, since nftables shares one kernel rule between
// ACL rules that generate the same spec.
func TestSetEgressRoutesEgressAclRules(t *testing.T) {
	src6 := "2001:db8::2/128"
	first := egressUpdate("8080", src6, src6)
	reinstall := []string{"DeleteAllAclEgressRules acl#egress-1", "AddAclEgressRules acl#egress-1"}
	cases := []struct {
		name   string
		second map[string]models.EgressInfo
		want   []string
	}{
		{"unchanged", first, nil},
		{"port changed", egressUpdate("9090", src6, src6), reinstall},
		{"destination6 changed", egressUpdate("8080", src6, "2001:db8::1/128"), reinstall},
		{"egress removed", map[string]models.EgressInfo{}, []string{"RemoveRoutingRules egress-1", "DeleteAllAclEgressRules acl#egress-1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := &fakeEgressController{table: ruletable{
				"egress-1":     {rulesMap: map[string][]ruleInfo{}, extraInfo: first["egress-1"].EgressGWCfg},
				"acl#egress-1": {extraInfo: first["egress-1"].EgressFwRules},
			}}
			prev := fwCrtl
			fwCrtl = fake
			t.Cleanup(func() { fwCrtl = prev })
			if err := SetEgressRoutes("server", c.second); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(fake.calls, c.want) {
				t.Fatalf("calls = %v, want %v", fake.calls, c.want)
			}
		})
	}
}
