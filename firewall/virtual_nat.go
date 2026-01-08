package firewall

import (
	"fmt"
	"net"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// virtualNatInfo holds virtual NAT configuration extracted from models
type virtualNatInfo struct {
	virtualRange net.IPNet
	realRange    net.IPNet
}

// extractVirtualNatInfoFromRange extracts virtual NAT info from EgressRangeMetric
// Virtual NAT is enabled when VirtualNetwork field is set (not empty)
func extractVirtualNatInfoFromRange(egressGwRange models.EgressRangeMetric) *virtualNatInfo {
	// Check if VirtualNetwork is set
	if egressGwRange.VirtualNetwork == "" {
		return nil
	}

	// Parse virtual network CIDR
	virtualRange := config.ToIPNet(egressGwRange.VirtualNetwork)
	if virtualRange.IP == nil {
		logger.Log(1, "invalid VirtualNetwork in egress range:", egressGwRange.VirtualNetwork)
		return nil
	}

	// Parse real network CIDR
	realRange := config.ToIPNet(egressGwRange.Network)
	if realRange.IP == nil {
		logger.Log(1, "invalid Network in egress range:", egressGwRange.Network)
		return nil
	}

	return &virtualNatInfo{
		virtualRange: virtualRange,
		realRange:    realRange,
	}
}

// shouldApplyVirtualNat checks if virtual NAT should be applied for this egress range
// Virtual NAT is enabled when VirtualNetwork field is set and Nat is true
func shouldApplyVirtualNat(egressGwRange models.EgressRangeMetric) (*virtualNatInfo, bool) {
	// Virtual NAT requires both Nat=true and VirtualNetwork to be set
	if !egressGwRange.Nat || egressGwRange.VirtualNetwork == "" {
		return nil, false
	}

	vnatInfo := extractVirtualNatInfoFromRange(egressGwRange)
	if vnatInfo != nil {
		return vnatInfo, true
	}

	return nil, false
}

// getVNATChainNames returns the chain names for virtual NAT rules
func getVNATChainNames(egressID string) (preroutingChain, postroutingChain, forwardChain string) {
	id8 := getEgressID8(egressID)
	preroutingChain = fmt.Sprintf("NM-VNAT-PR-%s", id8)
	postroutingChain = fmt.Sprintf("NM-VNAT-PO-%s", id8)
	forwardChain = fmt.Sprintf("NM-VNAT-FW-%s", id8)
	return
}
