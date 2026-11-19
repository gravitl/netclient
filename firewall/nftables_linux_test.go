package firewall

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/mdlayher/netlink"
)

// TestInboundAclRulesKeyedByOwner covers ACL changes where another ACL produces the same
// match: each ACL must keep its own rule key, or it replaces the other's rule and
// deleting either ACL removes the rule for both.
func TestInboundAclRulesKeyedByOwner(t *testing.T) {
	const server = "acl-rule-key-test"
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
			if bytes.Contains(message.Data, []byte(aclInputRulesChain+"\x00")) &&
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

	ProcessAclRules(server, &models.FwUpdate{AclRules: map[string]models.AclRule{"acl-a": rule("acl-a"), "acl-b": rule("acl-b")}})
	ProcessAclRules(server, &models.FwUpdate{AclRules: map[string]models.AclRule{"acl-c": rule("acl-c")}})

	if len(keys) != 3 {
		t.Fatalf("%s got %d ACL rules for three ACL IDs with the same match, want 3", aclInputRulesChain, len(keys))
	}
	seen := make(map[string]bool, len(keys))
	for _, key := range keys {
		if seen[key] {
			t.Fatalf("%s has two ACL rules with the same key", aclInputRulesChain)
		}
		seen[key] = true
	}
	all := strings.Join(keys, "\n")
	for _, id := range []string{"acl-a", "acl-b", "acl-c"} {
		if !strings.Contains(all, id) {
			t.Errorf("no %s rule key names its ACL ID %s", aclInputRulesChain, id)
		}
	}
}

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
