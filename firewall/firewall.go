package firewall

import (
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

var (
	fwCrtl firewallController
)

type rulesCfg struct {
	isIpv4   bool
	rulesMap map[string][]ruleInfo
}

type ruleInfo struct {
	rule   []string
	nfRule any
	table  string
	chain  string
}
type ruletable map[string]rulesCfg

type serverrulestable map[string]ruletable

const (
	ingressTable = "ingress"
	egressTable  = "egress"
)

type firewallController interface {
	// CreateChains  creates a firewall chains and jump rules
	CreateChains() error
	// ForwardRule inserts forwarding rules
	ForwardRule() error
	// InsertEgressRoutingRules - adds a egress routing rules for egressGw
	InsertEgressRoutingRules(server string, egressInfo models.EgressInfo) error
	// RemoveRoutingRules removes all routing rules firewall rules of a peer
	RemoveRoutingRules(server, tableName, peerKey string) error
	// DeleteRoutingRule removes rules related to a peer
	DeleteRoutingRule(server, tableName, srcPeer, dstPeer string) error
	// CleanRoutingRules cleans a firewall set of containers related to a server
	CleanRoutingRules(server, tableName string)
	// FetchRules - fetches current state of rules from controller
	FetchRuleTable(server, ruleTableName string) ruletable
	// DeleteRuleTable - deletes the entire rule table by server
	DeleteRuleTable(server, ruleTableName string)
	// SaveRules - saves the ruleTable under the given server
	SaveRules(server, ruleTableName string, ruleTable ruletable)
	// FlushAll - clears all rules from netmaker chains and deletes the chains
	FlushAll()
}

// Init - initialises the firewall controller,return a close func to flush all rules
func Init() (func(), error) {
	var err error
	logger.Log(0, "Starting firewall...")
	fwCrtl, err = newFirewall()
	if err != nil {
		return nil, err
	}
	if err := fwCrtl.CreateChains(); err != nil {
		return fwCrtl.FlushAll, err
	}
	err = fwCrtl.ForwardRule()
	if err != nil {
		return fwCrtl.FlushAll, err
	}
	return fwCrtl.FlushAll, nil
}
