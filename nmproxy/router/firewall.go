package router

import (
	"context"

	"github.com/coreos/go-iptables/iptables"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	fwCrtl  firewallController
	running bool
)

type firewallController interface {
	// CreateChains  creates a firewall chains and default rules
	CreateChains() error
	// InsertRoutingRules inserts a routing firewall rule
	InsertIngressRoutingRules(r ingressRoute) error
	// RemoveRoutingRules removes all routing rules firewall rules of a peer
	RemoveRoutingRules(peerKey wgtypes.Key) error
	// DeleteRoutingRule removes rules related to a peer
	DeleteRoutingRule(srcPeer, dstPeer wgtypes.Key) error
	// CleanRoutingRules cleans a firewall set of containers
	CleanRoutingRules()
}

func Init(ctx context.Context) error {
	fwCrtl = newFirewall(ctx)
	return fwCrtl.CreateChains()
}

// newFirewall if supported, returns an iptables manager, otherwise returns a nftables manager
func newFirewall(parentCTX context.Context) firewallController {

	var manager firewallController
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
			ingRules:   make(map[string]map[string][]RuleInfo),
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

func FlushAllRulesForPeer(peerKey wgtypes.Key) {
	fwCrtl.RemoveRoutingRules(peerKey)
}

func DeletePeerRoute(indexedPeerKey, peerKey wgtypes.Key) {

}
