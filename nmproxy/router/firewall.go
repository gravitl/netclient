package router

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
	rule  []string
	table string
	chain string
}
type ruletable map[string]rulesCfg

type serverrulestable map[string]ruletable

const (
	ingressTable = "ingress"
)

type firewallController interface {
	// CreateChains  creates a firewall chains and jump rules
	CreateChains() error
	// InsertIngressRoutingRules inserts a routing firewall rules for ingressGW
	InsertIngressRoutingRules(server string, r models.ExtClientInfo) error
	// AddIngRoutingRule - adds a ingress routing rule for a remote client wrt it's peer
	AddIngressRoutingRule(server, extPeerKey string, peerInfo models.PeerExtInfo) error
	// RemoveRoutingRules removes all routing rules firewall rules of a peer
	RemoveRoutingRules(server, tableName, peerKey string) error
	// DeleteRoutingRule removes rules related to a peer
	DeleteRoutingRule(server, tableName, srcPeer, dstPeer string) error
	// CleanRoutingRules cleans a firewall set of containers related to a server
	CleanRoutingRules(server, tableName string)
	// FetchRules - fetches current state of rules from controller
	FetchRuleTable(server string, ruleTableName string) ruletable
	// SaveRules - saves the ruleTable under the given server
	SaveRules(server, ruleTableName string, ruleTable ruletable)
	// FlushAll - clears all rules from netmaker chains and deletes the chains
	FlushAll()
}

// Init - initialises the firewall controller,return a close func to flush all rules
func Init() (func(), error) {
	logger.Log(0, "Starting firewall...")
	fwCrtl = newFirewall()
	if err := fwCrtl.CreateChains(); err != nil {
		return fwCrtl.FlushAll, err
	}
	return fwCrtl.FlushAll, nil
}
