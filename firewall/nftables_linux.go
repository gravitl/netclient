package firewall

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

type nftablesManager struct {
	conn         *nftables.Conn
	ingRules     serverrulestable
	engressRules serverrulestable
	mux          sync.Mutex
}

func init() {
	nfJumpRules = append(nfJumpRules, nfFilterJumpRules...)
	nfJumpRules = append(nfJumpRules, nfNatJumpRules...)
}

var (
	filterTable = &nftables.Table{Name: defaultIpTable, Family: nftables.TableFamilyINet}
	natTable    = &nftables.Table{Name: defaultNatTable, Family: nftables.TableFamilyINet}

	nfJumpRules []ruleInfo
	// filter table netmaker jump rules
	dropRule = ruleInfo{
		nfRule: &nftables.Rule{
			Table: filterTable,
			Chain: &nftables.Chain{Name: netmakerFilterChain},
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
				},
				&expr.Counter{},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
			UserData: []byte(genRuleKey("-i", ncutils.GetInterfaceName(), "-j", "DROP")),
		},
		rule:  []string{"-i", ncutils.GetInterfaceName(), "-j", "DROP"},
		table: defaultIpTable,
		chain: netmakerFilterChain,
	}
	nfFilterJumpRules = []ruleInfo{
		{
			nfRule: &nftables.Rule{
				Table: filterTable,
				Chain: &nftables.Chain{Name: netmakerFilterChain},
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
					},
					&expr.Counter{},
					&expr.Verdict{Kind: expr.VerdictReturn},
				},
				UserData: []byte(genRuleKey("-i", ncutils.GetInterfaceName(), "-j", "RETURN")),
			},
			rule:  []string{"-i", ncutils.GetInterfaceName(), "-j", "RETURN"},
			table: defaultIpTable,
			chain: netmakerFilterChain,
		},
		{
			nfRule: &nftables.Rule{
				Table: filterTable,
				Chain: &nftables.Chain{Name: iptableFWDChain},
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
					},
					&expr.Counter{},
					&expr.Verdict{Kind: expr.VerdictJump, Chain: netmakerFilterChain},
				},
				UserData: []byte(genRuleKey("-i", ncutils.GetInterfaceName(), "-j", netmakerFilterChain)),
			},
			rule:  []string{"-i", ncutils.GetInterfaceName(), "-j", netmakerFilterChain},
			table: defaultIpTable,
			chain: netmakerFilterChain,
		},
	}
	// nat table nm jump rules
	nfNatJumpRules = []ruleInfo{
		{
			nfRule: &nftables.Rule{
				Table: natTable,
				Chain: &nftables.Chain{Name: nattablePRTChain},
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
					},
					&expr.Counter{},
					&expr.Verdict{Kind: expr.VerdictJump, Chain: netmakerNatChain},
				},
				UserData: []byte(genRuleKey("-o", ncutils.GetInterfaceName(), "-j", netmakerNatChain)),
			},
			rule:  []string{"-o", ncutils.GetInterfaceName(), "-j", netmakerNatChain},
			table: defaultNatTable,
			chain: nattablePRTChain,
		},
		{
			nfRule: &nftables.Rule{
				Table: natTable,
				Chain: &nftables.Chain{Name: netmakerNatChain},
				Exprs: []expr.Any{
					&expr.Counter{},
					&expr.Verdict{Kind: expr.VerdictReturn},
				},
				UserData: []byte(genRuleKey("-j", "RETURN")),
			},
			rule:  []string{"-j", "RETURN"},
			table: defaultNatTable,
			chain: netmakerNatChain,
		},
	}
)

// nftables.CreateChains - creates default chains and rules
func (n *nftablesManager) CreateChains() error {
	n.mux.Lock()
	defer n.mux.Unlock()
	// remove jump rules
	n.removeJumpRules()

	n.conn.AddTable(filterTable)
	n.conn.AddTable(natTable)

	if err := n.conn.Flush(); err != nil {
		return err
	}

	n.deleteChain(defaultIpTable, netmakerFilterChain)
	n.deleteChain(defaultNatTable, netmakerNatChain)

	defaultForwardPolicy := new(nftables.ChainPolicy)
	*defaultForwardPolicy = nftables.ChainPolicyAccept

	forwardChain := &nftables.Chain{
		Name:     iptableFWDChain,
		Table:    filterTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   defaultForwardPolicy,
	}
	n.conn.AddChain(forwardChain)

	n.conn.AddChain(&nftables.Chain{
		Name:     "INPUT",
		Table:    filterTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})
	n.conn.AddChain(&nftables.Chain{
		Name:     "OUTPUT",
		Table:    filterTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
	})

	postroutingChain := &nftables.Chain{
		Name:     nattablePRTChain,
		Table:    natTable,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	}
	n.conn.AddChain(postroutingChain)

	n.conn.AddChain(&nftables.Chain{
		Name:     "PREROUTING",
		Table:    natTable,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	})
	n.conn.AddChain(&nftables.Chain{
		Name:     "INPUT",
		Table:    natTable,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityNATSource,
	})
	n.conn.AddChain(&nftables.Chain{
		Name:     "OUTPUT",
		Table:    natTable,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityNATDest,
	})

	filterChain := &nftables.Chain{
		Name:  netmakerFilterChain,
		Table: filterTable,
	}
	n.conn.AddChain(filterChain)

	natChain := &nftables.Chain{
		Name:  netmakerNatChain,
		Table: natTable,
	}
	n.conn.AddChain(natChain)

	if err := n.conn.Flush(); err != nil {
		return err
	}
	// add jump rules
	n.addJumpRules()
	return nil
}

// nftables.ForwardRule - forward netmaker traffic (not implemented)
func (n *nftablesManager) ForwardRule() error {
	if err := n.CreateChains(); err != nil {
		return err
	}
	n.deleteRule(dropRule.table, dropRule.chain, genRuleKey(dropRule.rule...))
	n.conn.AddRule(&nftables.Rule{
		Table: filterTable,
		Chain: &nftables.Chain{Name: iptableFWDChain},

		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
	return n.conn.Flush()
}

// nftables.CleanRoutingRules cleans existing nftable resources that we created by the agent
func (n *nftablesManager) CleanRoutingRules(server, ruleTableName string) {
	ruleTable := n.FetchRuleTable(server, ruleTableName)
	defer n.DeleteRuleTable(server, ruleTableName)
	n.mux.Lock()
	defer n.mux.Unlock()
	for _, rulesCfg := range ruleTable {
		for _, rules := range rulesCfg.rulesMap {
			for _, rule := range rules {
				if err := n.deleteRule(rule.table, rule.chain, genRuleKey(rule.rule...)); err != nil {
					logger.Log(0, "Error cleaning up rule: ", err.Error())
				}
			}
		}
	}
}

// nftables.DeleteRuleTable - deletes all rules from a table
func (n *nftablesManager) DeleteRuleTable(server, ruleTableName string) {
	n.mux.Lock()
	defer n.mux.Unlock()
	logger.Log(1, "Deleting rules table: ", server, ruleTableName)
	switch ruleTableName {
	case ingressTable:
		delete(n.ingRules, server)
	case egressTable:
		delete(n.engressRules, server)
	}
}

// nftables.InsertEgressRoutingRules - inserts egress routes for the GW peers
func (n *nftablesManager) InsertEgressRoutingRules(server string, egressInfo models.EgressInfo) error {
	ruleTable := n.FetchRuleTable(server, egressTable)
	defer n.SaveRules(server, egressTable, ruleTable)
	n.mux.Lock()
	defer n.mux.Unlock()
	// add jump Rules for egress GW
	var (
		rule           *nftables.Rule
		isIpv4         = isAddrIpv4(egressInfo.EgressGwAddr.String())
		egressGwRoutes = []ruleInfo{}
	)
	ruleTable[egressInfo.EgressID] = rulesCfg{
		isIpv4:   isIpv4,
		rulesMap: make(map[string][]ruleInfo),
	}
	for _, egressGwRange := range egressInfo.EgressGWCfg.Ranges {
		if egressInfo.EgressGWCfg.NatEnabled == "yes" {
			if egressRangeIface, err := getInterfaceName(config.ToIPNet(egressGwRange)); err != nil {
				logger.Log(0, "failed to get interface name: ", egressRangeIface, err.Error())
			} else {
				ruleSpec := []string{"-o", egressRangeIface, "-j", "MASQUERADE"}
				// to avoid duplicate iface route rule,delete if exists
				n.deleteRule(defaultNatTable, nattablePRTChain, genRuleKey(ruleSpec...))
				if isIpv4 {
					rule = &nftables.Rule{
						Table:    natTable,
						Chain:    &nftables.Chain{Name: nattablePRTChain, Table: natTable},
						UserData: []byte(genRuleKey(ruleSpec...)),
						Exprs: []expr.Any{
							&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
							&expr.Cmp{
								Op:       expr.CmpOpEq,
								Register: 1,
								Data:     []byte(egressRangeIface + "\x00"),
							},
							&expr.Counter{},
							&expr.Masq{},
						},
					}
				} else {
					rule = &nftables.Rule{
						Table:    natTable,
						Chain:    &nftables.Chain{Name: nattablePRTChain, Table: natTable},
						UserData: []byte(genRuleKey(ruleSpec...)),
						Exprs: []expr.Any{
							&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
							&expr.Cmp{
								Op:       expr.CmpOpEq,
								Register: 1,
								Data:     []byte(egressRangeIface + "\x00"),
							},
							&expr.Counter{},
							&expr.Masq{},
						},
					}
				}
				n.conn.InsertRule(rule)
				if err := n.conn.Flush(); err != nil {
					logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
				} else {
					egressGwRoutes = append(egressGwRoutes, ruleInfo{
						nfRule: rule,
						table:  defaultNatTable,
						chain:  nattablePRTChain,
						rule:   ruleSpec,
					})
				}
			}
		}
	}
	ruleTable[egressInfo.EgressID].rulesMap[egressInfo.EgressID] = egressGwRoutes

	return nil
}

// nftables.FetchRuleTable - fetches the rule table by table name
func (n *nftablesManager) FetchRuleTable(server string, tableName string) ruletable {
	n.mux.Lock()
	defer n.mux.Unlock()
	var rules ruletable
	switch tableName {
	case ingressTable:
		rules = n.ingRules[server]
		if rules == nil {
			rules = make(ruletable)
		}
	case egressTable:
		rules = n.engressRules[server]
		if rules == nil {
			rules = make(ruletable)
		}
	}
	return rules
}

// nftables.SaveRules - saves the rule table by tablename
func (n *nftablesManager) SaveRules(server, tableName string, rules ruletable) {
	n.mux.Lock()
	defer n.mux.Unlock()
	logger.Log(0, "Saving rules to table: ", tableName)
	switch tableName {
	case ingressTable:
		n.ingRules[server] = rules
	case egressTable:
		n.engressRules[server] = rules
	}
}

// nftables.RemoveRoutingRules removes an nfatbles rules related to a peer
func (n *nftablesManager) RemoveRoutingRules(server, ruletableName, peerKey string) error {
	rulesTable := n.FetchRuleTable(server, ruletableName)
	defer n.SaveRules(server, ruletableName, rulesTable)
	n.mux.Lock()
	defer n.mux.Unlock()
	if _, ok := rulesTable[peerKey]; !ok {
		return errors.New("peer not found in rule table: " + peerKey)
	}
	for _, rules := range rulesTable[peerKey].rulesMap {
		for _, rule := range rules {
			if err := n.deleteRule(rule.table, rule.chain, genRuleKey(rule.rule...)); err != nil {
				return fmt.Errorf("nftables: error while removing existing %s rules [%v] for %s: %v",
					rule.table, rule.rule, peerKey, err)
			}
		}
	}
	delete(rulesTable, peerKey)
	return nil
}

// nftables.DeleteRoutingRule - removes an nftables rule pair from forwarding and nat chains
func (n *nftablesManager) DeleteRoutingRule(server, ruletableName, srcPeerKey, dstPeerKey string) error {
	rulesTable := n.FetchRuleTable(server, ruletableName)
	defer n.SaveRules(server, ruletableName, rulesTable)
	n.mux.Lock()
	defer n.mux.Unlock()
	if _, ok := rulesTable[srcPeerKey]; !ok {
		return errors.New("peer not found in rule table: " + srcPeerKey)
	}
	if rules, ok := rulesTable[srcPeerKey].rulesMap[dstPeerKey]; ok {
		for _, rule := range rules {
			if err := n.deleteRule(rule.table, rule.chain, genRuleKey(rule.rule...)); err != nil {
				return fmt.Errorf("nftables: error while removing existing %s rules [%v] for %s: %v",
					rule.table, rule.rule, srcPeerKey, err)
			}
		}
	} else {
		return errors.New("rules not found for: " + dstPeerKey)
	}
	return nil
}

// nftables.FlushAll - removes all the rules added by netmaker and deletes the netmaker chains
func (n *nftablesManager) FlushAll() {
	n.mux.Lock()
	defer n.mux.Unlock()
	n.conn.FlushTable(filterTable)
	n.conn.FlushTable(natTable)
	if err := n.conn.Flush(); err != nil {
		logger.Log(0, "Error flushing tables: ", err.Error())
	}
}

// private functions

//lint:ignore U1000 might be useful in future
func (n *nftablesManager) getTable(tableName string) (*nftables.Table, error) {
	tables, err := n.conn.ListTables()
	if err != nil {
		return nil, err
	}
	for idx := range tables {
		if tables[idx].Name == tableName {
			return tables[idx], nil
		}
	}
	return nil, errors.New("No such table exists: " + tableName)
}

func (n *nftablesManager) getChain(tableName, chainName string) (*nftables.Chain, error) {
	chains, err := n.conn.ListChains()
	if err != nil {
		return nil, err
	}
	for idx := range chains {
		if chains[idx].Name == chainName && chains[idx].Table.Name == tableName {
			return chains[idx], nil
		}
	}
	return nil, fmt.Errorf("chain %s doesnt exists for table %s: ", chainName, tableName)
}

func (n *nftablesManager) getRule(tableName, chainName, ruleKey string) (*nftables.Rule, error) {
	rules, err := n.conn.GetRules(
		&nftables.Table{Name: tableName, Family: nftables.TableFamilyINet},
		&nftables.Chain{Name: chainName})
	if err != nil {
		return nil, err
	}
	for idx := range rules {
		if string(rules[idx].UserData) == ruleKey {
			return rules[idx], nil
		}
	}
	return nil, errors.New("No such rule exists: " + ruleKey)
}

func (n *nftablesManager) deleteChain(table, chain string) {
	chainObj, err := n.getChain(table, chain)
	if err != nil {
		logger.Log(0, fmt.Sprintf("failed to fetch chain: %s", err.Error()))
		return
	}
	n.conn.DelChain(chainObj)
	if err := n.conn.Flush(); err != nil {
		logger.Log(0, fmt.Sprintf("failed to delete chain: %s", err.Error()))
	}
}

func (n *nftablesManager) deleteRule(tableName, chainName, ruleKey string) error {
	rule, err := n.getRule(tableName, chainName, ruleKey)
	if err != nil {
		return err
	}
	if err := n.conn.DelRule(rule); err != nil {
		return err
	}
	return n.conn.Flush()
}

func (n *nftablesManager) addJumpRules() {
	for _, rule := range nfFilterJumpRules {
		n.conn.AddRule(rule.nfRule.(*nftables.Rule))
	}
	for _, rule := range nfNatJumpRules {
		n.conn.AddRule(rule.nfRule.(*nftables.Rule))
	}
	if err := n.conn.Flush(); err != nil {
		logger.Log(0, fmt.Sprintf("failed to add jump rules, Err: %s", err.Error()))
	}
}

func (n *nftablesManager) removeJumpRules() {
	for _, rule := range nfJumpRules {
		r := rule.nfRule.(*nftables.Rule)
		if err := n.deleteRule(r.Table.Name, r.Chain.Name, string(r.UserData)); err != nil {
			logger.Log(0, fmt.Sprintf("failed to rm rule: %v, Err: %v ", rule.rule, err.Error()))
		}
	}
}

func genRuleKey(rule ...string) string {
	return strings.Join(rule, ":")
}
