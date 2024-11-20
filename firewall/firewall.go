package firewall

import (
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

var (
	fwCrtl firewallController
)

type rulesCfg struct {
	isIpv4    bool
	rulesMap  map[string][]ruleInfo
	extraInfo interface{}
}

type ruleInfo struct {
	rule   []string
	isIpv4 bool
	nfRule any
	table  string
	chain  string
}
type ruletable map[string]rulesCfg

type serverrulestable map[string]ruletable

const (
	ingressTable = "ingress"
	egressTable  = "egress"
	aclTable     = "acl"
)

const (
	staticNodeRules = "static-node"
)

type firewallController interface {
	// CreateChains  creates a firewall chains and jump rules
	CreateChains() error
	// ForwardRule inserts forwarding rules
	ForwardRule() error
	// Add DROP Rules
	AddDropRules([]ruleInfo)
	// InsertEgressRoutingRules - adds a egress routing rules for egressGw
	InsertEgressRoutingRules(server string, egressInfo models.EgressInfo) error
	// InsertIngressRoutingRules - inserts fw rules on ingress gw
	InsertIngressRoutingRules(server string, ingressInfo models.IngressInfo) error
	// AddAclRules - inserts all rules related to acl policy
	AddAclRules(server string, aclRules map[string]models.AclRule)
	// UpsertAclRules - update a acl policy rules
	UpsertAclRule(server string, aclRule models.AclRule)
	// DeleteAclRule - cleanup all the rules associated with a acl policy
	DeleteAclRule(server, aclID string)
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
		return func() {}, err
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
