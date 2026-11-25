package firewall

import (
	"bytes"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/gravitl/netclient/config"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestAddJumpRulesDNSAllowMatchesUDPByL4Proto(t *testing.T) {
	const serverName = "dns-allow-l4proto-test"

	previousServer := config.GetServer(serverName)
	previousCurrServer := config.CurrServer
	config.UpdateServer(serverName, config.Server{})
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

	marshal := func(e expr.Any) []byte {
		b, err := expr.Marshal(byte(nftables.TableFamilyINet), e)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	dnsDport := marshal(&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, 0x35}})
	ipv4Proto := marshal(&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1})
	l4proto := marshal(&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
	udp := marshal(&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}})
	for _, req := range requests {
		if !bytes.Contains(req.Data, []byte(aclInputRulesChain+"\x00")) || !bytes.Contains(req.Data, dnsDport) {
			continue
		}
		if bytes.Contains(req.Data, ipv4Proto) {
			t.Errorf("DNS allow rule in %s matches the protocol at network header offset 9 (IPv4 only)", aclInputRulesChain)
		}
		if !bytes.Contains(req.Data, l4proto) || !bytes.Contains(req.Data, udp) {
			t.Errorf("DNS allow rule in %s does not match UDP by meta l4proto", aclInputRulesChain)
		}
		return
	}
	t.Fatalf("DNS allow rule was not added to %s", aclInputRulesChain)
}
