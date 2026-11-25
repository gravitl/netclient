package tracker

import (
	"net"
	"net/netip"
	"testing"

	pbflow "github.com/gravitl/netmaker/grpc/flow"
	"github.com/gravitl/netmaker/models"
	ct "github.com/ti-mo/conntrack"
)

func mustIPNet(t *testing.T, addr, cidr string) (net.IPNet, net.IPNet) {
	t.Helper()
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return net.IPNet{IP: net.ParseIP(addr), Mask: network.Mask}, *network
}

func TestInferNetworkAndDirection(t *testing.T) {
	addrA, rangeA := mustIPNet(t, "198.51.100.3", "198.51.100.0/24")
	addrB, rangeB := mustIPNet(t, "203.0.113.7", "203.0.113.0/24")
	_, rangeA6 := mustIPNet(t, "2001:db8:a::3", "2001:db8:a::/64")
	addrB6, _ := mustIPNet(t, "2001:db8:b::7", "2001:db8:b::/64")
	nodes := []models.CommonNode{
		{Network: "net-a", Address: addrA, NetworkRange: rangeA, NetworkRange6: rangeA6},
		{Network: "net-b", Address: addrB, NetworkRange: rangeB, Address6: addrB6},
	}
	tr := &FlowTracker{nodeIter: func(f func(node *models.CommonNode) bool) {
		for i := range nodes {
			if !f(&nodes[i]) {
				return
			}
		}
	}}

	tests := []struct {
		name, origSrc, origDst, replySrc, replyDst, wantNetwork string
		wantDirection                                           pbflow.Direction
	}{
		{"local egress", "198.51.100.3", "192.0.2.222", "192.0.2.222", "198.51.100.3", "net-a", pbflow.Direction_DIR_EGRESS},
		{"local ingress", "192.0.2.222", "198.51.100.3", "198.51.100.3", "192.0.2.222", "net-a", pbflow.Direction_DIR_INGRESS},
		{"lan to non-mesh destination source-NATed onto node address", "192.0.2.10", "192.0.2.222", "192.0.2.222", "203.0.113.7", "net-b", pbflow.Direction_DIR_EGRESS},
		{"ipv6 to mesh range keeps range match over source-NAT fallback", "2001:db8:ffff::10", "2001:db8:a::20", "2001:db8:a::20", "2001:db8:b::7", "net-a", pbflow.Direction_DIR_EGRESS},
		{"ipv6 lan to non-mesh destination source-NATed onto node address", "2001:db8:ffff::10", "2001:db8:ffff::20", "2001:db8:ffff::20", "2001:db8:b::7", "net-b", pbflow.Direction_DIR_EGRESS},
		{"unrelated flow without NAT", "192.0.2.10", "192.0.2.222", "192.0.2.222", "192.0.2.10", "", pbflow.Direction_DIR_UNSPECIFIED},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := &ct.Flow{
				TupleOrig:  ct.Tuple{IP: ct.IPTuple{SourceAddress: netip.MustParseAddr(tt.origSrc), DestinationAddress: netip.MustParseAddr(tt.origDst)}},
				TupleReply: ct.Tuple{IP: ct.IPTuple{SourceAddress: netip.MustParseAddr(tt.replySrc), DestinationAddress: netip.MustParseAddr(tt.replyDst)}},
			}
			gotNetwork, gotDirection := tr.inferNetworkAndDirection(flow)
			if gotNetwork != tt.wantNetwork || gotDirection != tt.wantDirection {
				t.Errorf("inferNetworkAndDirection() = (%q, %v), want (%q, %v)", gotNetwork, gotDirection, tt.wantNetwork, tt.wantDirection)
			}
		})
	}
}
