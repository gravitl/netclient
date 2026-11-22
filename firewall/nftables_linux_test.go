package firewall

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/mdlayher/netlink"
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

// egressAclOwnerKey is the owner digest the ACL chains key their rules by.
func egressAclOwnerKey(aclID string) string {
	sum := sha256.Sum256([]byte(aclID))
	return hex.EncodeToString(sum[:4])
}

// TestEgressAclRulesKeyedByOwner is the egress counterpart on NETMAKER-ACL-FWD: ACL IDs
// with the same match must not share a rule key.
func TestEgressAclRulesKeyedByOwner(t *testing.T) {
	const server = "egress-acl-rule-key-test"
	rule := func(id string) models.AclRule {
		return models.AclRule{
			ID:              id,
			IPList:          []net.IPNet{{IP: net.ParseIP("192.0.2.2"), Mask: net.CIDRMask(32, 32)}},
			AllowedProtocol: models.TCP,
			AllowedPorts:    []string{"22"},
			Allowed:         true,
		}
	}
	var keys []string
	conn, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		for _, message := range req {
			if bytes.Contains(message.Data, []byte(aclFwdRulesChain+"\x00")) &&
				bytes.Contains(message.Data, []byte("-s:192.0.2.2/32")) {
				keys = append(keys, string(message.Data))
			}
		}
		return req, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	previous := fwCrtl
	fwCrtl = &nftablesManager{conn: conn, ingRules: make(serverrulestable), engressRules: make(serverrulestable), aclRules: make(serverrulestable)}
	t.Cleanup(func() { fwCrtl = previous })

	egress := func(id string) map[string]models.EgressInfo {
		return map[string]models.EgressInfo{"egress": {EgressID: "egress", EgressFwRules: map[string]models.AclRule{id: rule(id)}}}
	}
	processEgressFwRules(server, egress("acl-a"))
	processEgressFwRules(server, egress("acl-b"))

	if len(keys) != 2 {
		t.Fatalf("%s got %d ACL rules for two ACL IDs with the same match, want 2", aclFwdRulesChain, len(keys))
	}
	seen := make(map[string]bool, len(keys))
	for _, key := range keys {
		if seen[key] {
			t.Fatalf("%s has two ACL rules with the same key", aclFwdRulesChain)
		}
		seen[key] = true
	}
	all := strings.Join(keys, "\n")
	for _, id := range []string{"acl-a", "acl-b"} {
		if !strings.Contains(all, egressAclOwnerKey(id)) {
			t.Errorf("no %s rule key carries the owner key of ACL %s", aclFwdRulesChain, id)
		}
	}
}

// TestEgressAclRulesLongRuleFitsUserDataLimit covers the 256 byte limit the kernel puts
// on NFTA_RULE_USERDATA. The key of this 33 port rule is 253 bytes with the owner digest,
// the length it has on develop, and 311 bytes when the netmaker signature and the full
// ACL ID both go into it, so the rule has to be installed with the digest as its only
// comment.
func TestEgressAclRulesLongRuleFitsUserDataLimit(t *testing.T) {
	const server = "egress-acl-long-rule-key-test"
	const aclID = "3f2b8c1e-3f4a-4c5b-8d6e-7a8b9c0d1e2f"
	ports := make([]string, 0, 33)
	for port := 1001; port <= 1033; port++ {
		ports = append(ports, strconv.Itoa(port))
	}
	var messages []netlink.Message
	conn, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		messages = append(messages, req...)
		return req, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	previous := fwCrtl
	fwCrtl = &nftablesManager{conn: conn, ingRules: make(serverrulestable), engressRules: make(serverrulestable), aclRules: make(serverrulestable)}
	t.Cleanup(func() { fwCrtl = previous })

	processEgressFwRules(server, map[string]models.EgressInfo{"egress": {
		EgressID: "egress",
		EgressFwRules: map[string]models.AclRule{aclID: {
			ID:              aclID,
			IPList:          []net.IPNet{{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(32, 32)}},
			Dst:             []net.IPNet{{IP: net.ParseIP("192.0.2.20"), Mask: net.CIDRMask(32, 32)}},
			AllowedProtocol: models.TCP,
			AllowedPorts:    ports,
			Allowed:         true,
		}},
	}})

	rules := fwCrtl.(*nftablesManager).engressRules[server]["acl#egress"].rulesMap[aclID]
	if len(rules) != 1 {
		t.Fatalf("%s got %d ACL rules for the long rule, want 1", aclFwdRulesChain, len(rules))
	}
	key := genRuleKey(rules[0].rule...)
	if len(key) > 256 {
		t.Fatalf("%s rule key is %d bytes, want at most 256: %s", aclFwdRulesChain, len(key), key)
	}
	if strings.Contains(key, netmakerSignature) {
		t.Fatalf("%s rule key still carries the %s comment: %s", aclFwdRulesChain, netmakerSignature, key)
	}
	for _, message := range messages {
		if bytes.Contains(message.Data, []byte(key)) {
			return
		}
	}
	t.Fatalf("%s long ACL rule with a %d byte key was not installed", aclFwdRulesChain, len(key))
}
