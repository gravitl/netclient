package firewall

import (
	"errors"
	"runtime"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// TestCreateChainsAddsEachForwardJumpOnce needs CAP_SYS_ADMIN to create its network
// namespace, which the non-root CI runner lacks, so run it manually with:
//
//	sudo go test ./firewall -run TestCreateChainsAddsEachForwardJumpOnce
func TestCreateChainsAddsEachForwardJumpOnce(t *testing.T) {
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skip("needs CAP_SYS_ADMIN to create a network namespace")
		}
		t.Fatal(err)
	}

	manager := &nftablesManager{conn: &nftables.Conn{}}
	assertEachForwardJumpOnce := func() {
		t.Helper()
		rules, err := manager.conn.GetRules(filterTable, &nftables.Chain{Name: iptableFWDChain, Table: filterTable})
		if err != nil {
			t.Fatalf("get rules of chain %s: %v", iptableFWDChain, err)
		}
		counts := make(map[string]int)
		for _, rule := range rules {
			counts[string(rule.UserData)]++
		}
		for _, ruleInfo := range nfFilterJumpRules {
			nfRule := ruleInfo.nfRule.(*nftables.Rule)
			if nfRule.Chain.Name != iptableFWDChain {
				continue
			}
			if n := counts[string(nfRule.UserData)]; n != 1 {
				t.Errorf("rule %v appears %d times in %s, want once", ruleInfo.rule, n, iptableFWDChain)
			}
		}
		// The conntrack established/related accepts must stay in front of the jumps.
		for i := 0; i < 2; i++ {
			if isJumpRule(rules[i]) {
				t.Errorf("%s rule %d is a jump, want a conntrack accept first", iptableFWDChain, i)
			}
		}
	}

	if err := manager.CreateChains(); err != nil {
		t.Fatalf("create chains: %v", err)
	}
	assertEachForwardJumpOnce()

	// The daemon resets its chains with FlushAll followed by CreateChains.
	manager.FlushAll()
	if err := manager.CreateChains(); err != nil {
		t.Fatalf("create chains after flush: %v", err)
	}
	assertEachForwardJumpOnce()
}

func isJumpRule(rule *nftables.Rule) bool {
	for _, e := range rule.Exprs {
		if verdict, ok := e.(*expr.Verdict); ok && verdict.Kind == expr.VerdictJump {
			return true
		}
	}
	return false
}
