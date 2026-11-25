package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/schema"
)

// TestInsertEgressRoutingRulesKeepsEveryVirtualNATRange inserts two virtual NAT ranges of one
// egress twice. The ranges share the egress VNAT chains, so after each insert every range must
// keep exactly one NETMAP and one MASQUERADE rule there, behind exactly one jump per chain.
func TestInsertEgressRoutingRulesKeepsEveryVirtualNATRange(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "iptables"), []byte(fakeIptables), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IPT_STATE", dir)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH")) // checkNETMAPSupport runs iptables from PATH
	client, err := iptables.New(iptables.Path(filepath.Join(dir, "iptables")))
	if err != nil {
		t.Fatal(err)
	}
	manager := &iptablesManager{ipv4Client: client, engressRules: make(serverrulestable)}
	ranges := [][2]string{{"192.0.2.10/32", "198.51.100.10/32"}, {"192.0.2.20/32", "198.51.100.20/32"}}
	if _, err := getInterfaceName(config.ToIPNet(ranges[0][0])); err != nil {
		t.Skipf("virtual NAT needs a route to %s: %v", ranges[0][0], err)
	}
	egress := models.EgressInfo{EgressID: "0123abcd-vnat-multi-range"}
	for _, r := range ranges {
		egress.EgressGWCfg.RangesWithMetric = append(egress.EgressGWCfg.RangesWithMetric,
			models.EgressRangeMetric{Network: r[0], VirtualNetwork: r[1], Nat: true, Mode: schema.VirtualNAT})
	}
	pr, po := getVNATChainNames(egress.EgressID)
	// count returns how many rules of a nat chain contain every part.
	count := func(chain string, parts ...string) (n int) {
		b, _ := os.ReadFile(filepath.Join(dir, "nat."+chain))
		for _, rule := range strings.Split(string(b), "\n") {
			has := rule != ""
			for _, part := range parts {
				has = has && strings.Contains(rule+" ", part+" ")
			}
			if has {
				n++
			}
		}
		return n
	}
	for insert := 1; insert <= 2; insert++ {
		if err := manager.InsertEgressRoutingRules("vnat-test", egress); err != nil {
			t.Fatalf("insert %d: %v", insert, err)
		}
		if count(pr) != len(ranges) || count(po) != len(ranges) || count("PREROUTING", "-j "+pr) != 1 || count("POSTROUTING", "-j "+po) != 1 {
			t.Fatalf("insert %d: want %d rules per VNAT chain and one jump to each, got %d, %d and %d, %d",
				insert, len(ranges), count(pr), count(po), count("PREROUTING", "-j "+pr), count("POSTROUTING", "-j "+po))
		}
		for _, r := range ranges {
			if count(pr, "-d "+r[1], "-j NETMAP", "--to "+r[0]) != 1 || count(po, "-i netmaker", "-d "+r[0], "-j MASQUERADE") != 1 {
				t.Errorf("insert %d: want one NETMAP %s to %s and one MASQUERADE for it", insert, r[1], r[0])
			}
		}
	}
}

// fakeIptables stands in for the iptables binary with the part of the CLI go-iptables uses here:
// it keeps each chain as a file <table>.<chain> of rule lines under $IPT_STATE and refuses to
// delete a chain that a rule still jumps to, as iptables does. No root or netns is needed.
const fakeIptables = `#!/bin/sh
[ "$1" = --version ] && { echo 'iptables v1.8.10 (legacy)'; exit 0; }
a=
for x in "$@"; do [ "$x" = --wait ] || a="$a|$x"; done
set -f; set -- $(echo "$a" | tr '|' ' '); set +f
[ "$1" = -t ] && [ "$3" != -j ] || exit 0
t=$2 c=$3 ch=$4 f=$IPT_STATE/$2.$4
shift 3; [ $# -gt 0 ] && shift
case $c in
-N) [ -e "$f" ] && exit 1; :>"$f" ;;
-F) [ -e "$f" ] && :>"$f" ;;
-X) grep -qs -e "-j $ch " "$IPT_STATE/$t".* && exit 1; rm -f "$f" ;;
-A) echo "$*" >>"$f" ;;
-I) shift; { echo "$*"; cat "$f" 2>/dev/null; } >"$f.n"; mv "$f.n" "$f" ;;
-C) [ -e "$f" ] && grep -qxF "$*" "$f" ;;
-D) grep -qxF "$*" "$f" 2>/dev/null || exit 1; grep -vxF "$*" "$f" >"$f.n"; mv "$f.n" "$f" ;;
-S) for g in "$IPT_STATE/$t".*; do [ ! -e "$g" ] || echo "-N ${g##*/$t.}"; done ;;
esac
`
