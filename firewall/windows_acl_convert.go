package firewall

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

// ACL layer selectors mirrored from firewall/wfp.Layer (keep values in sync).
const (
	aclLayerInbound = 0
	aclLayerForward = 1
)

const (
	aclProtoAny  uint8 = 0
	aclProtoICMP uint8 = 1
	aclProtoTCP  uint8 = 6
	aclProtoUDP  uint8 = 17
)

type aclFilterSpec struct {
	Name       string
	Layer      int
	SrcNets    []net.IPNet
	DstNets    []net.IPNet
	Protocol   uint8
	DstPort    uint16
	DstPortMax uint16
}

func aclToFilterSpecs(acl models.AclRule, layer int) []aclFilterSpec {
	proto := aclProtocol(acl.AllowedProtocol)
	ports := acl.AllowedPorts
	if layer == aclLayerForward && len(ports) > 0 {
		slog.Debug("windows: WFP IPFORWARD ACL ignores destination ports (no L4 fields)",
			"acl", acl.ID, "ports", ports)
		ports = nil
	}
	if len(ports) == 0 {
		ports = []string{""}
	}

	var specs []aclFilterSpec
	families := []struct {
		srcs, dsts []net.IPNet
	}{
		{acl.IPList, acl.Dst},
		{acl.IP6List, acl.Dst6},
	}
	idx := 0
	for _, fam := range families {
		if len(fam.srcs) == 0 {
			continue
		}
		for _, port := range ports {
			lo, hi, ok := parsePortRange(port)
			if !ok {
				slog.Warn("windows: skipping ACL port spec that cannot be parsed",
					"acl", acl.ID, "port", port)
				continue
			}
			name := fmt.Sprintf("nm-acl-%s-%d", winAclIDHash(acl.ID), idx)
			idx++
			specs = append(specs, aclFilterSpec{
				Name:       name,
				Layer:      layer,
				SrcNets:    append([]net.IPNet(nil), fam.srcs...),
				DstNets:    append([]net.IPNet(nil), fam.dsts...),
				Protocol:   proto,
				DstPort:    lo,
				DstPortMax: hi,
			})
		}
	}
	return specs
}

func aclProtocol(p models.Protocol) uint8 {
	switch strings.ToLower(p.String()) {
	case "tcp":
		return aclProtoTCP
	case "udp":
		return aclProtoUDP
	case "icmp":
		return aclProtoICMP
	default:
		return aclProtoAny
	}
}

// parsePortRange returns inclusive bounds for a port spec; hi is 0 for a single
// port. An empty spec means "all ports" and is valid. ok is false for anything
// unparsable, which callers must drop: a spec with no port condition allows
// every port, so guessing here would widen the rule instead of narrowing it.
func parsePortRange(port string) (uint16, uint16, bool) {
	port = strings.TrimSpace(port)
	if port == "" {
		return 0, 0, true
	}
	port = strings.ReplaceAll(port, ":", "-")
	if loStr, hiStr, isRange := strings.Cut(port, "-"); isRange {
		lo, loErr := strconv.ParseUint(strings.TrimSpace(loStr), 10, 16)
		hi, hiErr := strconv.ParseUint(strings.TrimSpace(hiStr), 10, 16)
		if loErr != nil || hiErr != nil || lo == 0 || hi < lo {
			return 0, 0, false
		}
		if hi == lo {
			return uint16(lo), 0, true
		}
		return uint16(lo), uint16(hi), true
	}
	v, err := strconv.ParseUint(port, 10, 16)
	if err != nil || v == 0 {
		return 0, 0, false
	}
	return uint16(v), 0, true
}
