package firewall

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// constants needed to manage and create iptable rules
const (
	ipv6                = "ipv6"
	ipv4                = "ipv4"
	defaultIpTable      = "filter"
	netmakerFilterChain = "netmakerfilter"
	defaultNatTable     = "nat"
	netmakerNatChain    = "netmakernat"
	iptableFWDChain     = "FORWARD"
	nattablePRTChain    = "POSTROUTING"
	netmakerSignature   = "NETMAKER"
)

type iptablesManager struct {
	ipv4Client   *iptables.IPTables
	ipv6Client   *iptables.IPTables
	ingRules     serverrulestable
	engressRules serverrulestable
	mux          sync.Mutex
}

var (
	dropRuleFilter = ruleInfo{

		rule:  []string{"-j", "DROP"},
		table: defaultIpTable,
		chain: netmakerFilterChain,
	}

	dropRuleNat = ruleInfo{

		rule:  []string{"-j", "DROP"},
		table: defaultNatTable,
		chain: netmakerNatChain,
	}

	// filter table netmaker jump rules
	filterNmJumpRules = []ruleInfo{
		{
			rule:  []string{"-j", "RETURN"},
			table: defaultIpTable,
			chain: netmakerFilterChain,
		},
	}
	// nat table nm jump rules
	natNmJumpRules = []ruleInfo{
		{
			rule: []string{"-o", ncutils.GetInterfaceName(), "-j", netmakerNatChain,
				"-m", "comment", "--comment", netmakerSignature},
			table: defaultNatTable,
			chain: nattablePRTChain,
		},
		{
			rule:  []string{"-j", "RETURN"},
			table: defaultNatTable,
			chain: netmakerNatChain,
		},
	}
)

func createChain(iptables *iptables.IPTables, table, newChain string) error {

	chains, err := iptables.ListChains(table)
	if err != nil {
		return fmt.Errorf("couldn't get %s %s table chains, error: %v", iptablesProtoToString(iptables.Proto()), table, err)
	}

	shouldCreateChain := true
	for _, chain := range chains {
		if chain == newChain {
			shouldCreateChain = false
		}
	}
	if shouldCreateChain {
		err = iptables.NewChain(table, newChain)
		if err != nil {
			return fmt.Errorf("couldn't create %s chain %s in %s table, error: %v", iptablesProtoToString(iptables.Proto()), newChain, table, err)
		}

	}
	return nil
}

// iptablesManager.ForwardRule inserts forwarding rules
func (i *iptablesManager) ForwardRule() error {
	i.mux.Lock()
	defer i.mux.Unlock()
	logger.Log(0, "adding forwarding rule")

	iptablesClient := i.ipv4Client
	// Set the policy To accept on forward chain
	iptablesClient.ChangePolicy(defaultIpTable, iptableFWDChain, "ACCEPT")
	// remove DROP rule if present
	iptablesClient.DeleteIfExists(dropRuleFilter.table, dropRuleFilter.chain, dropRuleFilter.rule...)
	iptablesClient.DeleteIfExists(dropRuleNat.table, dropRuleNat.chain, dropRuleNat.rule...)
	createChain(iptablesClient, defaultIpTable, netmakerFilterChain)
	ruleSpec := []string{"-i", "netmaker", "-j", "ACCEPT"}
	ruleSpec = appendNetmakerCommentToRule(ruleSpec)
	ok, err := i.ipv4Client.Exists(defaultIpTable, iptableFWDChain, ruleSpec...)
	if err == nil && !ok {
		if err := i.ipv4Client.Insert(defaultIpTable, iptableFWDChain, 1, ruleSpec...); err != nil {
			logger.Log(1, fmt.Sprintf("failed to add rule: %v Err: %v", ruleSpec, err.Error()))
		}
	}
	ok, err = i.ipv6Client.Exists(defaultIpTable, iptableFWDChain, ruleSpec...)
	if err == nil && !ok {
		if err := i.ipv6Client.Insert(defaultIpTable, iptableFWDChain, 1, ruleSpec...); err != nil {
			logger.Log(1, fmt.Sprintf("failed to add rule: %v Err: %v", ruleSpec, err.Error()))
		}
	}
	ruleSpec = []string{"-o", "netmaker", "-j", "ACCEPT"}
	ruleSpec = appendNetmakerCommentToRule(ruleSpec)
	ok, err = i.ipv4Client.Exists(defaultIpTable, iptableFWDChain, ruleSpec...)
	if err == nil && !ok {
		if err := i.ipv4Client.Insert(defaultIpTable, iptableFWDChain, 1, ruleSpec...); err != nil {
			logger.Log(1, fmt.Sprintf("failed to add rule: %v Err: %v", ruleSpec, err.Error()))
		}
	}
	ok, err = i.ipv6Client.Exists(defaultIpTable, iptableFWDChain, ruleSpec...)
	if err == nil && !ok {
		if err := i.ipv6Client.Insert(defaultIpTable, iptableFWDChain, 1, ruleSpec...); err != nil {
			logger.Log(1, fmt.Sprintf("failed to add rule: %v Err: %v", ruleSpec, err.Error()))
		}
	}
	return nil
}

// CleanRoutingRules cleans existing iptables resources that we created by the agent
func (i *iptablesManager) CleanRoutingRules(server, ruleTableName string) {
	ruleTable := i.FetchRuleTable(server, ruleTableName)
	defer i.DeleteRuleTable(server, ruleTableName)
	i.mux.Lock()
	defer i.mux.Unlock()
	for _, rulesCfg := range ruleTable {
		for key, rules := range rulesCfg.rulesMap {
			iptablesClient := i.ipv4Client
			if !rulesCfg.isIpv4 {
				iptablesClient = i.ipv6Client
			}
			for _, rule := range rules {
				err := iptablesClient.DeleteIfExists(rule.table, rule.chain, rule.rule...)
				if err != nil {
					logger.Log(1, fmt.Sprintf("failed to delete rule [%s]: %+v, Err: %s", key, rule, err.Error()))
				}
			}
		}
	}

}

// iptablesManager.CreateChains - creates default chains and rules
func (i *iptablesManager) CreateChains() error {
	i.mux.Lock()
	defer i.mux.Unlock()
	// remove jump rules
	i.removeJumpRules()
	i.cleanup(defaultIpTable, netmakerFilterChain)
	i.cleanup(defaultNatTable, netmakerNatChain)

	//errMSGFormat := "iptables: failed creating %s chain %s,error: %v"

	err := createChain(i.ipv4Client, defaultIpTable, netmakerFilterChain)
	if err != nil {
		logger.Log(1, "failed to create netmaker chain: ", err.Error())
		return err
	}
	err = createChain(i.ipv4Client, defaultNatTable, netmakerNatChain)
	if err != nil {
		logger.Log(1, "failed to create netmaker chain: ", err.Error())
		return err
	}

	err = createChain(i.ipv6Client, defaultIpTable, netmakerFilterChain)
	if err != nil {
		logger.Log(1, "failed to create netmaker chain: ", err.Error())
		return err
	}
	err = createChain(i.ipv6Client, defaultNatTable, netmakerNatChain)
	if err != nil {
		logger.Log(1, "failed to create netmaker chain: ", err.Error())
		return err
	}
	// add jump rules
	i.addJumpRules()
	return nil
}

func (i *iptablesManager) addJumpRules() {
	for _, rule := range filterNmJumpRules {
		err := i.ipv4Client.Append(rule.table, rule.chain, rule.rule...)
		if err != nil {
			logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", rule.rule, err.Error()))
		}
		err = i.ipv6Client.Append(rule.table, rule.chain, rule.rule...)
		if err != nil {
			logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", rule.rule, err.Error()))
		}
	}
	for _, rule := range natNmJumpRules {
		err := i.ipv4Client.Append(rule.table, rule.chain, rule.rule...)
		if err != nil {
			logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", rule.rule, err.Error()))
		}
		err = i.ipv6Client.Append(rule.table, rule.chain, rule.rule...)
		if err != nil {
			logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", rule.rule, err.Error()))
		}
	}
}

// checks if rule has been added by netmaker
func addedByNetmaker(ruleString string) bool {
	rule := strings.Fields(ruleString)
	for i, flag := range rule {
		if flag == "--comment" && len(rule)-1 > i {
			if rule[i+1] == netmakerSignature {
				return true
			}
		}
	}
	return false
}
func (i *iptablesManager) removeJumpRules() {
	rules, err := i.ipv4Client.List(defaultIpTable, iptableFWDChain)
	if err == nil {
		for _, rule := range rules {
			if addedByNetmaker(rule) {
				err := i.ipv4Client.Delete(defaultIpTable, iptableFWDChain, strings.Fields(rule)[2:]...)
				if err != nil {
					logger.Log(1, "failed to delete rule: ", rule, err.Error())
				}
			}
		}
	}
	rules, err = i.ipv6Client.List(defaultIpTable, iptableFWDChain)
	if err == nil {
		for _, rule := range rules {
			if addedByNetmaker(rule) {
				err := i.ipv6Client.Delete(defaultIpTable, iptableFWDChain, strings.Fields(rule)[2:]...)
				if err != nil {
					logger.Log(1, "failed to delete rule: ", rule, err.Error())
				}
			}
		}
	}
	rules, err = i.ipv4Client.List(defaultNatTable, nattablePRTChain)
	if err == nil {
		for _, rule := range rules {
			if addedByNetmaker(rule) {
				err := i.ipv4Client.Delete(defaultNatTable, nattablePRTChain, strings.Fields(rule)[2:]...)
				if err != nil {
					logger.Log(1, "failed to delete rule: ", rule, err.Error())
				}
			}
		}
	}
	rules, err = i.ipv6Client.List(defaultNatTable, nattablePRTChain)
	if err == nil {
		for _, rule := range rules {
			if addedByNetmaker(rule) {
				err := i.ipv6Client.Delete(defaultNatTable, nattablePRTChain, strings.Fields(rule)[2:]...)
				if err != nil {
					logger.Log(1, "failed to delete rule: ", rule, err.Error())
				}
			}
		}
	}

}

// iptablesManager.InsertEgressRoutingRules - inserts egress routes for the GW peers
func (i *iptablesManager) InsertEgressRoutingRules(server string, egressInfo models.EgressInfo) error {
	ruleTable := i.FetchRuleTable(server, egressTable)
	defer i.SaveRules(server, egressTable, ruleTable)
	i.mux.Lock()
	defer i.mux.Unlock()
	// add jump Rules for egress GW
	iptablesClient := i.ipv4Client
	isIpv4 := true
	if !isAddrIpv4(egressInfo.EgressGwAddr.String()) {
		iptablesClient = i.ipv6Client
		isIpv4 = false
	}
	ruleTable[egressInfo.EgressID] = rulesCfg{
		isIpv4:   isIpv4,
		rulesMap: make(map[string][]ruleInfo),
	}
	egressGwRoutes := []ruleInfo{}
	for _, egressGwRange := range egressInfo.EgressGWCfg.Ranges {
		if egressInfo.EgressGWCfg.NatEnabled == "yes" {
			egressRangeIface, err := getInterfaceName(config.ToIPNet(egressGwRange))
			if err != nil {
				logger.Log(0, "failed to get interface name: ", egressRangeIface, err.Error())
			} else {
				ruleSpec := []string{"-o", egressRangeIface, "-j", "MASQUERADE"}
				ruleSpec = appendNetmakerCommentToRule(ruleSpec)
				// to avoid duplicate iface route rule,delete if exists
				iptablesClient.DeleteIfExists(defaultNatTable, nattablePRTChain, ruleSpec...)
				err := iptablesClient.Insert(defaultNatTable, nattablePRTChain, 1, ruleSpec...)
				if err != nil {
					logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
				} else {
					egressGwRoutes = append(egressGwRoutes, ruleInfo{
						table: defaultNatTable,
						chain: nattablePRTChain,
						rule:  ruleSpec,
					})
				}
			}
		}
	}
	ruleTable[egressInfo.EgressID].rulesMap[egressInfo.EgressID] = egressGwRoutes

	return nil
}

// iptablesManager.AddEgressRoutingRule - inserts iptable rule for gateway peer
func (i *iptablesManager) AddEgressRoutingRule(server string, egressInfo models.EgressInfo,
	peer models.PeerRouteInfo) error {
	if !peer.Allow {
		return nil
	}
	ruleTable := i.FetchRuleTable(server, egressTable)
	defer i.SaveRules(server, egressTable, ruleTable)
	i.mux.Lock()
	defer i.mux.Unlock()
	iptablesClient := i.ipv4Client

	if !isAddrIpv4(egressInfo.EgressGwAddr.String()) {
		iptablesClient = i.ipv6Client
	}

	ruleSpec := []string{"-s", peer.PeerAddr.String(), "-d", strings.Join(egressInfo.EgressGWCfg.Ranges, ","), "-j", "ACCEPT"}
	err := iptablesClient.Insert(defaultIpTable, netmakerFilterChain, 1, ruleSpec...)
	if err != nil {
		logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
	} else {

		ruleTable[egressInfo.EgressID].rulesMap[peer.PeerKey] = []ruleInfo{
			{
				table: defaultIpTable,
				chain: netmakerFilterChain,
				rule:  ruleSpec,
			},
		}

	}

	return nil
}

func (i *iptablesManager) cleanup(table, chain string) {

	err := i.ipv4Client.ClearAndDeleteChain(table, chain)
	if err != nil {
		logger.Log(1, "[ipv4] failed to clear chain: ", table, chain, err.Error())
	}
	err = i.ipv6Client.ClearAndDeleteChain(table, chain)
	if err != nil {
		logger.Log(1, "[ipv6] failed to clear chain: ", table, chain, err.Error())
	}
}

// iptablesManager.FetchRuleTable - fetches the rule table by table name
func (i *iptablesManager) FetchRuleTable(server string, tableName string) ruletable {
	i.mux.Lock()
	defer i.mux.Unlock()
	var rules ruletable
	switch tableName {
	case ingressTable:
		rules = i.ingRules[server]
		if rules == nil {
			rules = make(ruletable)
		}
	case egressTable:
		rules = i.engressRules[server]
		if rules == nil {
			rules = make(ruletable)
		}
	}
	return rules
}

// iptablesManager.DeleteRuleTable - deletes all rules from a table
func (i *iptablesManager) DeleteRuleTable(server, ruleTableName string) {
	i.mux.Lock()
	defer i.mux.Unlock()
	logger.Log(1, "Deleting rules table: ", server, ruleTableName)
	switch ruleTableName {
	case ingressTable:
		delete(i.ingRules, server)
	case egressTable:
		delete(i.engressRules, server)
	}
}

// iptablesManager.SaveRules - saves the rule table by tablename
func (i *iptablesManager) SaveRules(server, tableName string, rules ruletable) {
	i.mux.Lock()
	defer i.mux.Unlock()
	logger.Log(1, "Saving rules to table: ", tableName)
	switch tableName {
	case ingressTable:
		i.ingRules[server] = rules
	case egressTable:
		i.engressRules[server] = rules
	}
}

// iptablesManager.RemoveRoutingRules removes an iptables rules related to a peer
func (i *iptablesManager) RemoveRoutingRules(server, ruletableName, peerKey string) error {
	rulesTable := i.FetchRuleTable(server, ruletableName)
	defer i.SaveRules(server, ruletableName, rulesTable)
	i.mux.Lock()
	defer i.mux.Unlock()
	if _, ok := rulesTable[peerKey]; !ok {
		return errors.New("peer not found in rule table: " + peerKey)
	}
	iptablesClient := i.ipv4Client
	if !rulesTable[peerKey].isIpv4 {
		iptablesClient = i.ipv6Client
	}

	for _, rules := range rulesTable[peerKey].rulesMap {
		for _, rule := range rules {
			err := iptablesClient.DeleteIfExists(rule.table, rule.chain, rule.rule...)
			if err != nil {
				return fmt.Errorf("iptables: error while removing existing %s rules [%v] for %s: %v",
					rule.table, rule.rule, peerKey, err)
			}
		}

	}
	delete(rulesTable, peerKey)
	return nil
}

// iptablesManager.DeleteRoutingRule - removes an iptables rule pair from forwarding and nat chains
func (i *iptablesManager) DeleteRoutingRule(server, ruletableName, srcPeerKey, dstPeerKey string) error {
	rulesTable := i.FetchRuleTable(server, ruletableName)
	defer i.SaveRules(server, ruletableName, rulesTable)
	i.mux.Lock()
	defer i.mux.Unlock()
	if _, ok := rulesTable[srcPeerKey]; !ok {
		return errors.New("peer not found in rule table: " + srcPeerKey)
	}
	iptablesClient := i.ipv4Client
	if !rulesTable[srcPeerKey].isIpv4 {
		iptablesClient = i.ipv6Client
	}
	if rules, ok := rulesTable[srcPeerKey].rulesMap[dstPeerKey]; ok {
		for _, rule := range rules {
			err := iptablesClient.DeleteIfExists(rule.table, rule.chain, rule.rule...)
			if err != nil {
				return fmt.Errorf("iptables: error while removing existing %s rules [%v] for %s: %v",
					rule.table, rule.rule, srcPeerKey, err)
			}
		}
		delete(rulesTable[srcPeerKey].rulesMap, dstPeerKey)
	} else {
		return errors.New("rules not found for: " + dstPeerKey)
	}

	return nil
}

// iptablesManager.FlushAll - removes all the rules added by netmaker and deletes the netmaker chains
func (i *iptablesManager) FlushAll() {
	i.mux.Lock()
	defer i.mux.Unlock()
	// remove jump rules
	i.removeJumpRules()
	i.cleanup(defaultIpTable, netmakerFilterChain)
	i.cleanup(defaultNatTable, netmakerNatChain)
}

func iptablesProtoToString(proto iptables.Protocol) string {
	if proto == iptables.ProtocolIPv6 {
		return ipv6
	}
	return ipv4
}

func appendNetmakerCommentToRule(ruleSpec []string) []string {
	ruleSpec = append(ruleSpec, "-m", "comment", "--comment", netmakerSignature)
	return ruleSpec
}
