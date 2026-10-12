package wireguard

import (
	"net"
	"testing"
)

func TestPickLiveLANGatewayPrefersLiveBetterMetric(t *testing.T) {
	remembered := net.ParseIP("10.0.0.1")
	live := net.ParseIP("10.1.0.1")
	idx, gw, metric, ok := pickLiveLANGateway([]lanRouteCandidate{
		{ifaceIdx: "12", gw: remembered, metric: 50, up: true},
		{ifaceIdx: "8", gw: net.ParseIP("100.64.0.1"), metric: 0, up: true, netmaker: true},
		{ifaceIdx: "3", gw: net.ParseIP("10.2.0.1"), metric: 0, up: false},
		{ifaceIdx: "20", gw: live, metric: 10, up: true},
	})
	if !ok {
		t.Fatal("expected a live gateway")
	}
	if idx != "20" || !gw.Equal(live) || metric != 10 {
		t.Fatalf("got idx=%s gw=%v metric=%d, want idx=20 gw=%v metric=10", idx, gw, metric, live)
	}
}

func TestPickLiveLANGatewayFromNetshDump(t *testing.T) {
	const dump = `
Publish  Type      Met  Prefix                    Idx  Gateway/Interface Name
-------  --------  ---  ------------------------  ---  ------------------------
No       Manual    50   0.0.0.0/0                 12   10.0.0.1
No       Manual    0    0.0.0.0/0                 20   10.1.0.1
No       Manual    0    0.0.0.0/0                  8   netmaker
No       Manual    256  10.1.0.0/24               20   10.1.0.1
`
	rows := parseNetshDefaultRoutes(dump, "0.0.0.0/0")
	if len(rows) != 3 {
		t.Fatalf("parsed %d default routes, want 3", len(rows))
	}
	var cands []lanRouteCandidate
	for _, row := range rows {
		if row.onLink {
			continue
		}
		cands = append(cands, lanRouteCandidate{
			ifaceIdx: row.ifaceIdx,
			gw:       row.gw,
			metric:   row.metric,
			up:       true,
			netmaker: row.ifaceIdx == "8",
		})
	}
	_, gw, _, ok := pickLiveLANGateway(cands)
	if !ok || !gw.Equal(net.ParseIP("10.1.0.1")) {
		t.Fatalf("picked %v ok=%v, want 10.1.0.1", gw, ok)
	}
}

func TestExitDefaultWins(t *testing.T) {
	if exitDefaultWins(nil) {
		t.Fatal("empty route table counted as the exit winning")
	}
	if !exitDefaultWins([]exitRouteScore{
		{effective: 25, netmaker: true},
		{effective: 75, netmaker: false},
	}) {
		t.Fatal("netmaker with the better effective metric should win")
	}
	if exitDefaultWins([]exitRouteScore{
		{effective: 25, netmaker: true},
		{effective: 25, netmaker: false},
	}) {
		t.Fatal("a tie with the ISP route counted as the exit winning")
	}
	metrics := parseNetshInterfaceMetrics(`
Idx     Met         MTU          State                Name
---  ----------  ----------  ------------  ---------------------------
  8          26        1420  connected     netmaker
 20          25        1500  connected     Ethernet
`)
	if metrics["8"] != 26 || metrics["20"] != 25 {
		t.Fatalf("interface metrics = %v", metrics)
	}
	rows := parseNetshDefaultRoutes(`
No       Manual    0    0.0.0.0/0                  8   netmaker
No       Manual    0    0.0.0.0/0                 20   10.1.0.1
`, "0.0.0.0/0")
	scores := make([]exitRouteScore, 0, len(rows))
	for _, row := range rows {
		scores = append(scores, exitRouteScore{
			effective: row.metric + metrics[row.ifaceIdx],
			netmaker:  row.ifaceIdx == "8",
		})
	}
	if exitDefaultWins(scores) {
		t.Fatal("new ISP default at metric 0 on a lower interface metric counted as the exit winning")
	}
}
