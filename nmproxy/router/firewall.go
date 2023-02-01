package router

import (
	"context"

	"github.com/coreos/go-iptables/iptables"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

var (
	fwCrtl  firewallController
	running bool
)

const (
	ingressTable = "ingress"
)

type firewallController interface {
	// CreateChains  creates a firewall chains and default rules
	CreateChains() error
	// InsertIngressRoutingRules inserts a routing firewall rules for ingressGW
	InsertIngressRoutingRules(server string, r models.ExtClientInfo) error
	// AddIngRoutingRule - adds a ingress routing rule for a remote client wrt it's peer
	AddIngRoutingRule(server, extPeerKey string, peerInfo models.PeerExtInfo) error
	// RemoveRoutingRules removes all routing rules firewall rules of a peer
	RemoveRoutingRules(server, tableName, peerKey string) error
	// DeleteRoutingRule removes rules related to a peer
	DeleteRoutingRule(server, tableName, srcPeer, dstPeer string) error
	// CleanRoutingRules cleans a firewall set of containers
	CleanRoutingRules(server, tableName string)
	// FetchRules - fetches current state of rules from controller
	FetchRuleTable(server string, ruleTableName string) ruletable
	// SaveRules - saves the ruleTable under the given server
	SaveRules(server, ruleTableName string, ruleTable ruletable)
}

type rulesCfg struct {
	isIpv4   bool
	rulesMap map[string][]RuleInfo
}
type ruletable map[string]rulesCfg

type serverrulestable map[string]ruletable

func Init(ctx context.Context) error {
	logger.Log(0, "Starting firewall...")
	fwCrtl = newFirewall(ctx)
	return fwCrtl.CreateChains()
}

// newFirewall if supported, returns an iptables manager, otherwise returns a nftables manager
func newFirewall(parentCTX context.Context) firewallController {

	var manager firewallController
	if isIptablesSupported() {
		logger.Log(0, "iptables is supported")
		ipv4Client, _ := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		ipv6Client, _ := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		ctx, cancel := context.WithCancel(parentCTX)
		manager = &iptablesManager{
			ctx:        ctx,
			stop:       cancel,
			ipv4Client: ipv4Client,
			ipv6Client: ipv6Client,
			ingRules:   make(serverrulestable),
		}
	}

	logger.Log(0, "iptables is not supported, using nftables")

	// manager := &nftablesManager{
	// 	ctx:    ctx,
	// 	stop:   cancel,
	// 	conn:   &nftables.Conn{},
	// 	chains: make(map[string]map[string]*nftables.Chain),
	// 	rules:  make(map[string]*nftables.Rule),
	// }

	return manager
}
