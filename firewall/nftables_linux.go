package firewall

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"

	"golang.org/x/exp/slog"

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
	nfDropRules = []ruleInfo{
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
					&expr.Verdict{Kind: expr.VerdictDrop},
				},
				UserData: []byte(genRuleKey("-i", ncutils.GetInterfaceName(), "-j", "DROP")),
			},
			rule:  []string{"-i", ncutils.GetInterfaceName(), "-j", "DROP"},
			table: defaultIpTable,
			chain: netmakerFilterChain,
		},
	}
	nfFilterJumpRules = []ruleInfo{
		// {
		// 	nfRule: &nftables.Rule{
		// 		Table: filterTable,
		// 		Chain: &nftables.Chain{Name: netmakerFilterChain},
		// 		Exprs: []expr.Any{
		// 			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		// 			&expr.Cmp{
		// 				Op:       expr.CmpOpEq,
		// 				Register: 1,
		// 				Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
		// 			},
		// 			&expr.Counter{},
		// 			&expr.Verdict{Kind: expr.VerdictReturn},
		// 		},
		// 		UserData: []byte(genRuleKey("-i", ncutils.GetInterfaceName(), "-j", "RETURN")),
		// 	},
		// 	rule:  []string{"-i", ncutils.GetInterfaceName(), "-j", "RETURN"},
		// 	table: defaultIpTable,
		// 	chain: netmakerFilterChain,
		// },
		// {
		// 	nfRule: &nftables.Rule{
		// 		Table: filterTable,
		// 		Chain: &nftables.Chain{Name: iptableFWDChain},
		// 		Exprs: []expr.Any{
		// 			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		// 			&expr.Cmp{
		// 				Op:       expr.CmpOpEq,
		// 				Register: 1,
		// 				Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
		// 			},
		// 			&expr.Counter{},
		// 			&expr.Verdict{Kind: expr.VerdictJump, Chain: netmakerFilterChain},
		// 		},
		// 		UserData: []byte(genRuleKey("-i", ncutils.GetInterfaceName(), "-j", netmakerFilterChain)),
		// 	},
		// 	rule:  []string{"-i", ncutils.GetInterfaceName(), "-j", netmakerFilterChain},
		// 	table: defaultIpTable,
		// 	chain: netmakerFilterChain,
		// },
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

func (n *nftablesManager) AddDropRules(dropRules []ruleInfo) {

	// Add a rule that matches packets on the 'netmaker' interface and drops them
	for _, dropRule := range dropRules {
		n.conn.AddRule(dropRule.nfRule.(*nftables.Rule))
	}
	// Apply the changes
	if err := n.conn.Flush(); err != nil {
		log.Fatalf("Failed to apply changes: %v", err)
	}
}

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
		Name:     iptableINChain,
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

			source := egressInfo.Network.String()
			if !isAddrIpv4(egressGwRange) {
				source = egressInfo.Network6.String()
			}
			if egressRangeIface, err := getInterfaceName(config.ToIPNet(egressGwRange)); err != nil {
				logger.Log(0, "failed to get interface name: ", egressRangeIface, err.Error())
			} else {
				ruleSpec := []string{"-s", source, "-o", egressRangeIface, "-j", "MASQUERADE"}
				// to avoid duplicate iface route rule,delete if exists
				var exp []expr.Any
				if isAddrIpv4(source) {
					exp = []expr.Any{
						// Match source IP address
						&expr.Payload{
							DestRegister: 1,
							Base:         expr.PayloadBaseNetworkHeader,
							Offset:       12, // Source address offset in IP header
							Len:          4,
						},
						&expr.Bitwise{
							SourceRegister: 1,
							DestRegister:   1,
							Len:            4,
							Mask:           egressInfo.Network.Mask, // /16 mask for 100.64.0.0/16
							Xor:            []byte{0, 0, 0, 0},
						},
						&expr.Cmp{
							Op:       expr.CmpOpEq,
							Register: 1,
							Data:     egressInfo.Network.IP.To4(), // 100.64.0.0/16
						},
						// Match outgoing interface by index
						&expr.Meta{
							Key:      expr.MetaKeyOIFNAME,
							Register: 1,
						},
						&expr.Cmp{
							Op:       expr.CmpOpEq,
							Register: 1,
							Data:     []byte(egressRangeIface), // Interface name with null terminator
						},
						// Perform masquerade
						&expr.Masq{},
					}
				} else {
					exp = []expr.Any{
						// Match source IPv6 address (2001:db8::/64)
						&expr.Payload{
							DestRegister: 1,
							Base:         expr.PayloadBaseNetworkHeader,
							Offset:       8,  // Source address offset in IPv6 header
							Len:          16, // Length of IPv6 address
						},
						&expr.Bitwise{
							SourceRegister: 1,
							DestRegister:   1,
							Len:            16,
							Mask:           egressInfo.Network6.Mask, // /64 mask
							Xor:            []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
						},
						&expr.Cmp{
							Op:       expr.CmpOpEq,
							Register: 1,
							Data:     egressInfo.Network6.IP.To16(), // 2001:db8::/64
						},
						// Match outgoing interface by name
						&expr.Meta{
							Key:      expr.MetaKeyOIFNAME,
							Register: 1,
						},
						&expr.Cmp{
							Op:       expr.CmpOpEq,
							Register: 1,
							Data:     []byte(egressRangeIface), // Interface name with null terminator
						},
						// Perform masquerade
						&expr.Masq{},
					}
				}

				n.deleteRule(defaultNatTable, nattablePRTChain, genRuleKey(ruleSpec...))
				rule = &nftables.Rule{
					Table:    natTable,
					Chain:    &nftables.Chain{Name: nattablePRTChain, Table: natTable},
					UserData: []byte(genRuleKey(ruleSpec...)),
					Exprs:    exp,
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
				slog.Debug("failed to del egress rule: ", "error", fmt.Errorf("nftables: error while removing existing %s rules [%v] for %s: %v",
					rule.table, rule.rule, peerKey, err))
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
	logger.Log(0, "flushing netmaker rules...")
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
	n.AddDropRules(nfDropRules)
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

func (n *nftablesManager) InsertIngressRoutingRules(server string, ingressInfo models.IngressInfo) error {
	ruleTable := n.FetchRuleTable(server, ingressTable)
	defer n.SaveRules(server, ingressTable, ruleTable)
	n.mux.Lock()
	defer n.mux.Unlock()
	var ingressRules rulesCfg
	var ok bool
	ingressRules, ok = ruleTable[ingressInfo.IngressID]
	if !ok {
		ingressRules = rulesCfg{
			rulesMap: make(map[string][]ruleInfo),
		}
	}
	ingressGwRoutes := []ruleInfo{}
	for _, ip := range ingressInfo.StaticNodeIps {
		network := ingressInfo.Network.String()
		if ip.To4() == nil {
			network = ingressInfo.Network6.String()
		}
		ruleSpec := []string{"-s", ip.String(), "-d", network, "-j", netmakerFilterChain}
		ruleSpec = appendNetmakerCommentToRule(ruleSpec)
		n.deleteRule(defaultIpTable, iptableINChain, genRuleKey(ruleSpec...))
		// to avoid duplicate iface route rule,delete if exists
		rule := &nftables.Rule{}
		if ip.To4() != nil {
			rule = &nftables.Rule{
				Table: filterTable,
				Chain: &nftables.Chain{Name: iptableINChain},
				Exprs: []expr.Any{
					// Match packets from source IP 100.59.157.250/32
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       12, // Source IP offset
						Len:          4,  // IPv4 address size
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     ip.To4(),
					},
					// Match packets to destination IP 100.59.157.0/24 using Bitwise operation
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       16, // Destination IP offset
						Len:          4,  // IPv4 address size
					},
					// Apply a bitwise AND operation to match the subnet
					&expr.Bitwise{
						SourceRegister: 1,
						DestRegister:   1,
						Len:            4,                        // Length of the IPv4 address
						Mask:           ingressInfo.Network.Mask, // /24 subnet mask
						Xor:            []byte{0, 0, 0, 0},       // No XOR
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     ingressInfo.Network.IP.To4(),
					},
					// Jump to the netmakerfilter chain
					&expr.Verdict{
						Kind:  expr.VerdictJump,
						Chain: netmakerFilterChain, // Jump to the netmakerfilter chain
					},
				},
				UserData: []byte(genRuleKey(ruleSpec...)), // Equivalent to the comment in iptables
			}
		} else {
			rule = &nftables.Rule{
				Table: filterTable,
				Chain: &nftables.Chain{Name: iptableINChain},
				Exprs: []expr.Any{
					// Match packets from source IP 2001:db8::1/128
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       8,  // IPv6 Source IP offset
						Len:          16, // IPv6 address length
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     ip.To16(), // IPv6 source address
					},
					// Match packets to destination IP 2001:db8::/64 using Bitwise operation
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       24, // IPv6 Destination IP offset
						Len:          16, // IPv6 address length
					},
					// Apply a bitwise AND operation to match the subnet
					&expr.Bitwise{
						SourceRegister: 1,
						DestRegister:   1,
						Len:            16,                                                     // Length of the IPv6 address
						Mask:           ingressInfo.Network6.Mask,                              // /64 subnet mask
						Xor:            []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // No XOR
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     ingressInfo.Network6.IP.To16(), // IPv6 destination network
					},
					// Jump to the netmakerfilter chain
					&expr.Verdict{
						Kind:  expr.VerdictJump,
						Chain: netmakerFilterChain, // Jump to the netmakerfilter chain
					},
				},
				UserData: []byte(genRuleKey(ruleSpec...)), // Equivalent to the comment in iptables
			}
		}

		n.conn.InsertRule(rule)
		if err := n.conn.Flush(); err != nil {
			logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
		} else {
			ingressGwRoutes = append(ingressGwRoutes, ruleInfo{
				nfRule: rule,
				table:  defaultIpTable,
				chain:  iptableINChain,
				rule:   ruleSpec,
			})
		}

		//  rule for FWD chain
		n.deleteRule(defaultIpTable, iptableFWDChain, genRuleKey(ruleSpec...))
		if ip.To4() != nil {
			rule = &nftables.Rule{
				Table: filterTable,
				Chain: &nftables.Chain{Name: iptableFWDChain},
				Exprs: []expr.Any{
					// Match packets from source IP 100.59.157.250/32
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       12, // Source IP offset
						Len:          4,  // IPv4 address size
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     ip.To4(),
					},
					// Match packets to destination IP 100.59.157.0/24 using Bitwise operation
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       16, // Destination IP offset
						Len:          4,  // IPv4 address size
					},
					// Apply a bitwise AND operation to match the subnet
					&expr.Bitwise{
						SourceRegister: 1,
						DestRegister:   1,
						Len:            4,                        // Length of the IPv4 address
						Mask:           ingressInfo.Network.Mask, // /24 subnet mask
						Xor:            []byte{0, 0, 0, 0},       // No XOR
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     ingressInfo.Network.IP.To4(),
					},
					// Jump to the netmakerfilter chain
					&expr.Verdict{
						Kind:  expr.VerdictJump,
						Chain: netmakerFilterChain, // Jump to the netmakerfilter chain
					},
				},
				UserData: []byte(genRuleKey(ruleSpec...)), // Equivalent to the comment in iptables
			}
		} else {
			rule = &nftables.Rule{
				Table: filterTable,
				Chain: &nftables.Chain{Name: iptableFWDChain},
				Exprs: []expr.Any{
					// Match packets from source IP 2001:db8::1/128
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       8,  // IPv6 Source IP offset
						Len:          16, // IPv6 address length
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     ip.To16(), // IPv6 source address
					},
					// Match packets to destination IP 2001:db8::/64 using Bitwise operation
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       24, // IPv6 Destination IP offset
						Len:          16, // IPv6 address length
					},
					// Apply a bitwise AND operation to match the subnet
					&expr.Bitwise{
						SourceRegister: 1,
						DestRegister:   1,
						Len:            16,                                                     // Length of the IPv6 address
						Mask:           ingressInfo.Network6.Mask,                              // /64 subnet mask
						Xor:            []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // No XOR
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     ingressInfo.Network6.IP.To16(), // IPv6 destination network
					},
					// Jump to the netmakerfilter chain
					&expr.Verdict{
						Kind:  expr.VerdictJump,
						Chain: netmakerFilterChain, // Jump to the netmakerfilter chain
					},
				},
				UserData: []byte(genRuleKey(ruleSpec...)), // Equivalent to the comment in iptables
			}
		}

		n.conn.InsertRule(rule)
		if err := n.conn.Flush(); err != nil {
			logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
		} else {
			ingressGwRoutes = append(ingressGwRoutes, ruleInfo{
				nfRule: rule,
				table:  defaultIpTable,
				chain:  iptableFWDChain,
				rule:   ruleSpec,
			})
		}
	}
	for _, rule := range ingressInfo.Rules {
		if !rule.Allow {
			continue
		}
		ruleSpec := []string{"-s", rule.SrcIP.String(), "-d",
			rule.DstIP.String(), "-j", "ACCEPT"}
		n.deleteRule(defaultIpTable, netmakerFilterChain, genRuleKey(ruleSpec...))
		ruleSpec = appendNetmakerCommentToRule(ruleSpec)
		var nfRule *nftables.Rule
		if rule.SrcIP.IP.To4() != nil {
			nfRule = &nftables.Rule{
				Table: filterTable,
				Chain: &nftables.Chain{Name: netmakerFilterChain},
				Exprs: []expr.Any{
					// Match packets from source IP 100.59.157.252/32
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       12, // IPv4 Source IP offset
						Len:          4,  // IPv4 address size
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     rule.SrcIP.IP.To4(), // IPv4 source address
					},
					// Match packets to destination IP 100.59.157.250/32
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       16, // IPv4 Destination IP offset
						Len:          4,  // IPv4 address size
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     rule.DstIP.IP.To4(), // IPv4 destination address
					},
					// Accept the packet
					&expr.Verdict{
						Kind: expr.VerdictAccept, // ACCEPT verdict
					},
				},
				UserData: []byte(genRuleKey(ruleSpec...)), // Equivalent to the comment in iptables
			}

		} else {
			nfRule = &nftables.Rule{
				Table: filterTable,
				Chain: &nftables.Chain{Name: netmakerFilterChain},
				Exprs: []expr.Any{
					// Match packets from source IP 2001:db8::1/128
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       8,  // IPv6 Source IP offset
						Len:          16, // IPv6 address length
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     rule.SrcIP.IP.To16(), // IPv6 source address
					},
					// Match packets to destination IP 2001:db8::2/128
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       24, // IPv6 Destination IP offset
						Len:          16, // IPv6 address length
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     rule.DstIP.IP.To16(), // IPv6 destination address
					},
					// Accept the packet
					&expr.Verdict{
						Kind: expr.VerdictAccept, // ACCEPT verdict
					},
				},
				UserData: []byte(genRuleKey(ruleSpec...)), // Equivalent to the comment in iptables
			}
		}
		n.conn.InsertRule(nfRule)
		if err := n.conn.Flush(); err != nil {
			logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
		} else {
			ingressGwRoutes = append(ingressGwRoutes, ruleInfo{
				table: defaultIpTable,
				chain: netmakerFilterChain,
				rule:  ruleSpec,
			})
		}
	}
	ingressRules.rulesMap[staticNodeRules] = ingressGwRoutes
	ingressRules.extraInfo = ingressInfo
	ruleTable[ingressInfo.IngressID] = ingressRules
	return nil
}

func (n *nftablesManager) AddAclRules(server string, aclRules map[string]models.AclRule) {

}

func (n *nftablesManager) UpsertAclRule(server string, aclRule models.AclRule) {

}

func (n *nftablesManager) DeleteAclRule(server, aclID string) {

}
