package wireguard

import (
	"net"
	"strconv"
	"strings"
)

// lanRouteCandidate is one default route considered when choosing the underlay
// gateway that exit pins should follow.
type lanRouteCandidate struct {
	ifaceIdx string
	gw       net.IP
	metric   int
	// up is false when the interface is down, so a leftover route from the
	// previous ISP is not selected.
	up       bool
	netmaker bool
}

// pickLiveLANGateway returns the lowest-metric candidate whose interface is
// up. Netmaker's own default route is ignored. The gateway saved when the
// exit connected does not outrank a live route with a better metric.
func pickLiveLANGateway(cands []lanRouteCandidate) (ifaceIdx string, gw net.IP, metric int, ok bool) {
	var chosen lanRouteCandidate
	found := false
	for _, c := range cands {
		if c.netmaker || !c.up || len(c.gw) == 0 || c.gw.IsUnspecified() {
			continue
		}
		if !found || c.metric < chosen.metric {
			chosen = c
			found = true
		}
	}
	if !found {
		return "", nil, 0, false
	}
	return chosen.ifaceIdx, chosen.gw, chosen.metric, true
}

// exitRouteScore is one default route's effective metric (route metric plus
// interface metric) and whether that route belongs to the netmaker interface.
type exitRouteScore struct {
	effective int
	netmaker  bool
}

// exitDefaultWins reports whether the best default route is the netmaker one.
// An equal effective metric on a non-exit route does not count as a win: the
// new ISP route would keep the traffic.
func exitDefaultWins(rows []exitRouteScore) bool {
	if len(rows) == 0 {
		return false
	}
	best := rows[0].effective
	bestNetmaker := rows[0].netmaker
	ambiguous := false
	for _, row := range rows[1:] {
		switch {
		case row.effective < best:
			best = row.effective
			bestNetmaker = row.netmaker
			ambiguous = false
		case row.effective == best && row.netmaker != bestNetmaker:
			ambiguous = true
		}
	}
	return bestNetmaker && !ambiguous
}

// netshDefaultRoute is one default-route row from `netsh int ipv4/ipv6 show route`.
type netshDefaultRoute struct {
	ifaceIdx string
	gw       net.IP
	metric   int
	onLink   bool
}

func netshLines(input string) []string {
	return strings.FieldsFunc(input, func(r rune) bool { return r == '\r' || r == '\n' })
}

func parseNetshDefaultRoutes(input, network string) []netshDefaultRoute {
	var out []netshDefaultRoute
	for _, line := range netshLines(input) {
		fields := strings.Fields(line)
		prefixAt := -1
		for i, f := range fields {
			if f == network {
				prefixAt = i
				break
			}
		}
		if prefixAt < 1 || prefixAt+1 >= len(fields) {
			continue
		}
		metric, err := strconv.Atoi(fields[prefixAt-1])
		if err != nil {
			continue
		}
		row := netshDefaultRoute{ifaceIdx: fields[prefixAt+1], metric: metric}
		if prefixAt+2 >= len(fields) {
			row.onLink = true
			out = append(out, row)
			continue
		}
		rest := strings.Join(fields[prefixAt+2:], " ")
		if ip := net.ParseIP(rest); ip != nil {
			row.gw = ip
		} else {
			row.onLink = true
		}
		out = append(out, row)
	}
	return out
}

func parseNetshInterfaceMetrics(input string) map[string]int {
	out := make(map[string]int)
	for _, line := range netshLines(input) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if _, err := strconv.Atoi(fields[0]); err != nil {
			continue
		}
		met, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		out[fields[0]] = met
	}
	return out
}
