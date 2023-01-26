package router

import (
	"context"
	"fmt"

	"github.com/coreos/go-iptables/iptables"
	log "github.com/sirupsen/logrus"
)

type firewallManager interface {
	// RestoreOrCreateContainers restores or creates a firewall container set of rules, tables and default rules
	RestoreOrCreateContainers() error
	// InsertRoutingRules inserts a routing firewall rule
	InsertRoutingRules(pair routerPair) error
	// RemoveRoutingRules removes a routing firewall rule
	RemoveRoutingRules(pair routerPair) error
	// CleanRoutingRules cleans a firewall set of containers
	CleanRoutingRules()
}

const (
	ipv6Forwarding     = "netmaker-rt-ipv6-forwarding"
	ipv4Forwarding     = "netmaker-rt-ipv4-forwarding"
	ipv6Nat            = "netmaker-rt-ipv6-nat"
	ipv4Nat            = "netmaker-rt-ipv4-nat"
	natFormat          = "netmaker-nat-%s"
	forwardingFormat   = "netmaker-fwd-%s"
	inNatFormat        = "netmaker-nat-in-%s"
	inForwardingFormat = "netmaker-fwd-in-%s"
	ipv6               = "ipv6"
	ipv4               = "ipv4"
)

func genKey(format string, input string) string {
	return fmt.Sprintf(format, input)
}

// NewFirewall if supported, returns an iptables manager, otherwise returns a nftables manager
func NewFirewall(parentCTX context.Context) firewallManager {

	var manager firewallManager
	if isIptablesSupported() {
		log.Debugf("iptables is supported")
		ipv4Client, _ := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		ipv6Client, _ := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		ctx, cancel := context.WithCancel(parentCTX)
		manager = &iptablesManager{
			ctx:        ctx,
			stop:       cancel,
			ipv4Client: ipv4Client,
			ipv6Client: ipv6Client,
			rules:      make(map[string]map[string][]string),
		}
	}

	//log.Debugf("iptables is not supported, using nftables")

	// manager := &nftablesManager{
	// 	ctx:    ctx,
	// 	stop:   cancel,
	// 	conn:   &nftables.Conn{},
	// 	chains: make(map[string]map[string]*nftables.Chain),
	// 	rules:  make(map[string]*nftables.Rule),
	// }

	return manager
}

func getInPair(pair routerPair) routerPair {
	return routerPair{
		ID: pair.ID,
		// invert source/destination
		source:      pair.destination,
		destination: pair.source,
		masquerade:  pair.masquerade,
	}
}
