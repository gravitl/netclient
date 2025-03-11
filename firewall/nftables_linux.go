package firewall

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"

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
	aclRules     serverrulestable
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
				Chain: &nftables.Chain{Name: aclInputRulesChain},
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
			chain: aclInputRulesChain,
		},
	}
	nfFilterJumpRules = []ruleInfo{
		{
			nfRule: &nftables.Rule{
				Table: filterTable,
				Chain: &nftables.Chain{Name: iptableINChain},
				Exprs: []expr.Any{
					// Match on input interface (-i netmaker)
					&expr.Meta{
						Key:      expr.MetaKeyIIFNAME, // Input interface name
						Register: 1,                   // Store in register 1
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,                                // Equals operation
						Register: 1,                                           // Compare register 1
						Data:     []byte(ncutils.GetInterfaceName() + "\x00"), // Interface name "netmaker" (null-terminated string)
					},
					// Match on conntrack state (-m conntrack --ctstate RELATED,ESTABLISHED)
					&expr.Ct{
						Key:      expr.CtKeySTATE,
						Register: 1,
					},
					&expr.Bitwise{
						SourceRegister: 1,                              // Use register 1 from Ct expression
						DestRegister:   1,                              // Output to same register
						Len:            4,                              // State length
						Mask:           []byte{0x06, 0x00, 0x00, 0x00}, // Mask for RELATED (2) and ESTABLISHED (4)
						Xor:            []byte{0x00, 0x00, 0x00, 0x00}, // No XOR
					},
					&expr.Cmp{
						Op:       expr.CmpOpNeq, // Check if the bitwise result is not zero
						Register: 1,
						Data:     []byte{0x00, 0x00, 0x00, 0x00},
					},
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
				UserData: []byte(genRuleKey("-i", ncutils.GetInterfaceName(), "-m", "conntrack",
					"--ctstate", "ESTABLISHED,RELATED", "-m", "comment",
					"--comment", netmakerSignature, "-j", "ACCEPT")), // Add comment
			},
			rule: []string{"-i", ncutils.GetInterfaceName(), "-m", "conntrack",
				"--ctstate", "ESTABLISHED,RELATED", "-m", "comment",
				"--comment", netmakerSignature, "-j", "ACCEPT"},
			table: defaultIpTable,
			chain: iptableINChain,
		},
		{

			nfRule: &nftables.Rule{
				Table: filterTable,
				Chain: &nftables.Chain{Name: iptableINChain},
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
					},
					&expr.Counter{},
					&expr.Verdict{
						Kind:  expr.VerdictJump,
						Chain: aclInputRulesChain,
					},
				},
				UserData: []byte(genRuleKey("-i", ncutils.GetInterfaceName(), "-j", aclInputRulesChain)),
			},
			rule:  []string{"-i", ncutils.GetInterfaceName(), "-j", aclInputRulesChain},
			table: defaultIpTable,
			chain: iptableINChain,
		},
		{
			nfRule: &nftables.Rule{
				Table: filterTable,
				Chain: &nftables.Chain{Name: iptableFWDChain},
				Exprs: []expr.Any{
					// Match on input interface (-i netmaker)
					&expr.Meta{
						Key:      expr.MetaKeyIIFNAME, // Input interface name
						Register: 1,                   // Store in register 1
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,                                // Equals operation
						Register: 1,                                           // Compare register 1
						Data:     []byte(ncutils.GetInterfaceName() + "\x00"), // Interface name "netmaker" (null-terminated string)
					},
					// Match on conntrack state (-m conntrack --ctstate RELATED,ESTABLISHED)
					&expr.Ct{
						Key:      expr.CtKeySTATE,
						Register: 1,
					},
					&expr.Bitwise{
						SourceRegister: 1,                              // Use register 1 from Ct expression
						DestRegister:   1,                              // Output to same register
						Len:            4,                              // State length
						Mask:           []byte{0x06, 0x00, 0x00, 0x00}, // Mask for RELATED (2) and ESTABLISHED (4)
						Xor:            []byte{0x00, 0x00, 0x00, 0x00}, // No XOR
					},
					&expr.Cmp{
						Op:       expr.CmpOpNeq, // Check if the bitwise result is not zero
						Register: 1,
						Data:     []byte{0x00, 0x00, 0x00, 0x00},
					},
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
				UserData: []byte(genRuleKey("-i", ncutils.GetInterfaceName(), "-m", "conntrack",
					"--ctstate", "ESTABLISHED,RELATED", "-m", "comment",
					"--comment", netmakerSignature, "-j", "ACCEPT")), // Add comment
			},
			rule: []string{"-i", ncutils.GetInterfaceName(), "-m", "conntrack",
				"--ctstate", "ESTABLISHED,RELATED", "-m", "comment",
				"--comment", netmakerSignature, "-j", "ACCEPT"},
			table: defaultIpTable,
			chain: iptableFWDChain,
		},
		{
			nfRule: &nftables.Rule{
				Table: filterTable,
				Chain: &nftables.Chain{Name: iptableFWDChain},
				Exprs: []expr.Any{
					// Match on input interface (-i netmaker)
					&expr.Meta{
						Key:      expr.MetaKeyOIFNAME, // Input interface name
						Register: 1,                   // Store in register 1
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,                                // Equals operation
						Register: 1,                                           // Compare register 1
						Data:     []byte(ncutils.GetInterfaceName() + "\x00"), // Interface name "netmaker" (null-terminated string)
					},
					// Match on conntrack state (-m conntrack --ctstate RELATED,ESTABLISHED)
					&expr.Ct{
						Key:      expr.CtKeySTATE,
						Register: 1,
					},
					&expr.Bitwise{
						SourceRegister: 1,                              // Use register 1 from Ct expression
						DestRegister:   1,                              // Output to same register
						Len:            4,                              // State length
						Mask:           []byte{0x06, 0x00, 0x00, 0x00}, // Mask for RELATED (2) and ESTABLISHED (4)
						Xor:            []byte{0x00, 0x00, 0x00, 0x00}, // No XOR
					},
					&expr.Cmp{
						Op:       expr.CmpOpNeq, // Check if the bitwise result is not zero
						Register: 1,
						Data:     []byte{0x00, 0x00, 0x00, 0x00},
					},
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
				UserData: []byte(genRuleKey("-o", ncutils.GetInterfaceName(), "-m", "conntrack",
					"--ctstate", "ESTABLISHED,RELATED", "-m", "comment",
					"--comment", netmakerSignature, "-j", "ACCEPT")), // Add comment
			},
			rule: []string{"-o", ncutils.GetInterfaceName(), "-m", "conntrack",
				"--ctstate", "ESTABLISHED,RELATED", "-m", "comment",
				"--comment", netmakerSignature, "-j", "ACCEPT"},
			table: defaultIpTable,
			chain: iptableFWDChain,
		},
		{
			nfRule: &nftables.Rule{
				Table: filterTable,
				Chain: &nftables.Chain{Name: iptableFWDChain},
				Exprs: []expr.Any{
					// Match input interface "netmaker"
					&expr.Meta{
						Key:      expr.MetaKeyIIFNAME,
						Register: 1,
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
					},

					// Match NOT output interface "netmaker"
					&expr.Meta{
						Key:      expr.MetaKeyOIFNAME,
						Register: 1,
					},
					&expr.Cmp{
						Op:       expr.CmpOpNeq,
						Register: 1,
						Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
					},
					// Accept the packet
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
			},
			rule:  []string{"-i", ncutils.GetInterfaceName(), "!", "-o", ncutils.GetInterfaceName(), "-j", targetAccept},
			table: defaultIpTable,
			chain: iptableFWDChain,
		},
		{
			nfRule: &nftables.Rule{
				Table: filterTable,
				Chain: &nftables.Chain{Name: iptableFWDChain},
				Exprs: []expr.Any{
					// Match input interface "netmaker"
					&expr.Meta{
						Key:      expr.MetaKeyIIFNAME,
						Register: 1,
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
					},

					// Match output interface "netmaker"
					&expr.Meta{
						Key:      expr.MetaKeyOIFNAME,
						Register: 1,
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
					},

					// Jump to NETMAKER-ACL-IN chain
					&expr.Verdict{
						Kind:  expr.VerdictJump,
						Chain: aclInputRulesChain,
					},
				},
				UserData: []byte(genRuleKey("-i", ncutils.GetInterfaceName(), "-o", ncutils.GetInterfaceName(), "-j", aclInputRulesChain,
					"-m", "comment", "--comment", netmakerSignature)),
			},
			rule: []string{"-i", ncutils.GetInterfaceName(), "-o", ncutils.GetInterfaceName(), "-j", aclInputRulesChain,
				"-m", "comment", "--comment", netmakerSignature},
			table: defaultIpTable,
			chain: iptableFWDChain,
		},
		{
			nfRule: &nftables.Rule{
				Table: filterTable,
				Chain: &nftables.Chain{Name: aclOutputRulesChain},
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
					},
					&expr.Counter{},
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
				UserData: []byte(genRuleKey("-o", ncutils.GetInterfaceName(), "-j", targetAccept)),
			},
			rule:  []string{"-o", ncutils.GetInterfaceName(), "-j", targetAccept},
			table: defaultIpTable,
			chain: aclOutputRulesChain,
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

func (n *nftablesManager) AddDropRules(dropRules []ruleInfo) {

	// Add a rule that matches packets on the 'netmaker' interface and drops them
	for _, dropRule := range dropRules {
		n.conn.AddRule(dropRule.nfRule.(*nftables.Rule))
	}
	// Apply the changes
	if err := n.conn.Flush(); err != nil {
		slog.Error("Failed to apply changes: %v", err)
	}
}

// nftables.CreateChains - creates default chains and rules
func (n *nftablesManager) CreateChains() error {
	n.mux.Lock()
	defer n.mux.Unlock()
	n.conn.AddTable(filterTable)
	n.conn.AddTable(natTable)

	if err := n.conn.Flush(); err != nil {
		return err
	}

	//defaultDropPolicy := nftables.ChainPolicyDrop
	defaultAcceptPolicy := new(nftables.ChainPolicy)
	*defaultAcceptPolicy = nftables.ChainPolicyAccept
	defaultForwardPolicy := new(nftables.ChainPolicy)
	*defaultForwardPolicy = nftables.ChainPolicyAccept
	n.conn.AddChain(&nftables.Chain{
		Name:     iptableINChain,
		Table:    filterTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   defaultAcceptPolicy,
	})
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

	aclInChain := &nftables.Chain{
		Name:  aclInputRulesChain,
		Table: filterTable,
	}
	n.conn.AddChain(aclInChain)
	n.conn.AddChain(&nftables.Chain{
		Name:  aclOutputRulesChain,
		Table: filterTable,
	})
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

	return nil
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
	case egressTable:
		rules = n.engressRules[server]
	case aclTable:
		rules = n.aclRules[server]
	}
	if rules == nil {
		rules = make(ruletable)
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
	case aclTable:
		n.aclRules[server] = rules
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

//lint:ignore U1000 might be useful in future
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
	// add metrics rule
	server := config.GetServer(config.CurrServer)
	if server != nil {
		var portNum uint16 = uint16(server.MetricsPort)

		// Convert to Little Endian bytes
		portB := make([]byte, 2) // Size of uint16 is 2 bytes
		binary.LittleEndian.PutUint16(portB, portNum)
		rule := &nftables.Rule{
			Table: filterTable,
			Chain: &nftables.Chain{Name: aclInputRulesChain},
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},                                        // Match incoming interface
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("netmaker\x00")},                   // Match interface name
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, // Match TCP destination port
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: portB},                                    // Port little-endian format
				&expr.Verdict{Kind: expr.VerdictAccept},                                                  // Accept packet
			},
		}
		n.conn.InsertRule(rule)
	}
	if err := n.conn.Flush(); err != nil {
		logger.Log(0, fmt.Sprintf("failed to add jump rules, Err: %s", err.Error()))
	}
	n.AddDropRules(nfDropRules)
}

//lint:ignore U1000 might be useful in future
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

func (n *nftablesManager) getExprForProto(proto models.Protocol, isv4 bool) []expr.Any {

	ipNetHeaderExpr := &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       9, // Offset for protocol in IPv4 header
		Len:          1, // Protocol field length
	}
	if !isv4 {
		ipNetHeaderExpr = &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       6, // Offset for "Next Header" field in IPv6 header
			Len:          1, // Length of the "Next Header" field
		}
	}
	var protoExpr *expr.Cmp
	switch proto {
	case models.UDP:

		protoExpr = &expr.Cmp{
			Register: 1,
			Op:       expr.CmpOpEq,
			Data:     []byte{syscall.IPPROTO_UDP}, // UDP protocol number
		}

	case models.TCP:
		protoExpr = &expr.Cmp{
			Register: 1,
			Op:       expr.CmpOpEq,
			Data:     []byte{syscall.IPPROTO_TCP}, // TCP protocol number
		}
	case models.ICMP:
		if isv4 {
			protoExpr = &expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     []byte{syscall.IPPROTO_ICMP}, // ICMP protocol number
			}
		} else {
			protoExpr = &expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     []byte{syscall.IPPROTO_ICMPV6}, // ICMP protocol number
			}
		}
	}
	return []expr.Any{
		ipNetHeaderExpr,
		protoExpr,
	}
}

func (n *nftablesManager) getExprForPort(ports []string) []expr.Any {
	var e []expr.Any

	ipTransPortHeader := &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       2, // Offset for destination port in TCP header
		Len:          2, // Port field length
	}
	for _, port := range ports {

		if strings.Contains(port, "-") {
			// Destination port range (8000-9000)
			ports := strings.Split(port, "-")
			startPortStr := ports[0]
			endPortStr := ports[1]
			startPortInt, err := strconv.Atoi(startPortStr)
			if err != nil {
				continue
			}
			endPortInt, err := strconv.Atoi(endPortStr)
			if err != nil {
				continue
			}
			startPort := uint16(startPortInt)
			endPort := uint16(endPortInt)
			startPortBytes := make([]byte, 2)
			endPortBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(startPortBytes, startPort)
			binary.BigEndian.PutUint16(endPortBytes, endPort)
			e = append(e, ipTransPortHeader, &expr.Range{
				Op:       expr.CmpOpEq,
				Register: 1,
				FromData: startPortBytes,
				ToData:   endPortBytes,
			})
		} else {
			portInt, err := strconv.Atoi(port)
			if err != nil {
				continue
			}
			dport := uint16(portInt)
			dPortBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(dPortBytes, dport)
			e = append(e, ipTransPortHeader, &expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     dPortBytes, // Port in network byte order
			})
		}
	}

	return e
}

func (n *nftablesManager) getRuleCnt(table *nftables.Table, chain *nftables.Chain) (cnt uint64) {
	// Fetch existing rules
	rules, err := n.conn.GetRules(table, chain)
	if err != nil {
		return
	}
	return uint64(len(rules))
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
		ruleSpec := []string{"-s", ip.String(), "-j", targetDrop}
		ruleSpec = appendNetmakerCommentToRule(ruleSpec)
		n.deleteRule(defaultIpTable, iptableINChain, genRuleKey(ruleSpec...))
		druleSpec := []string{"-d", ip.String(), "-j", targetDrop}
		druleSpec = appendNetmakerCommentToRule(druleSpec)
		n.deleteRule(defaultIpTable, iptableINChain, genRuleKey(druleSpec...))
		// to avoid duplicate iface route rule,delete if exists
		rule := &nftables.Rule{}
		drule := &nftables.Rule{}
		if ip.To4() != nil {
			rule = &nftables.Rule{
				Table: filterTable,
				Chain: &nftables.Chain{Name: aclInputRulesChain},
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
					// Jump to the netmakerfilter chain
					&expr.Verdict{
						Kind: expr.VerdictDrop,
					},
				},
				UserData: []byte(genRuleKey(ruleSpec...)), // Equivalent to the comment in iptables
			}
			drule = &nftables.Rule{
				Table: filterTable,
				Chain: &nftables.Chain{Name: aclInputRulesChain},
				Exprs: []expr.Any{
					// Match destination IP address
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       16, // IPv4 destination address starts at offset 16
						Len:          4,  // IPv4 addresses are 4 bytes
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     ip.To4(),
					},
					// Drop the packet
					&expr.Verdict{
						Kind: expr.VerdictDrop,
					},
				},
				UserData: []byte(genRuleKey(druleSpec...)),
			}
		} else {
			rule = &nftables.Rule{
				Table: filterTable,
				Chain: &nftables.Chain{Name: aclInputRulesChain},
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

					// Jump to the netmakerfilter chain
					&expr.Verdict{
						Kind: expr.VerdictDrop,
					},
				},
				UserData: []byte(genRuleKey(ruleSpec...)), // Equivalent to the comment in iptables
			}
			drule = &nftables.Rule{
				Table: filterTable,
				Chain: &nftables.Chain{Name: aclInputRulesChain},
				Exprs: []expr.Any{
					// Match destination IPv6 address
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       24, // IPv6 destination address starts at offset 24
						Len:          16, // IPv6 addresses are 16 bytes
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     ip.To16(),
					},
					// Drop the packet
					&expr.Verdict{
						Kind: expr.VerdictDrop,
					},
				},
				UserData: []byte(genRuleKey(druleSpec...)),
			}

		}
		rule.Position = n.getRuleCnt(rule.Table, rule.Chain) - 1
		if rule.Position < 1 {
			rule.Position = 0
		}
		n.conn.InsertRule(rule)
		drule.Position = rule.Position - 1
		if drule.Position < 1 {
			drule.Position = 0
		}
		n.conn.InsertRule(drule)
		if err := n.conn.Flush(); err != nil {
			logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
		} else {
			ingressGwRoutes = append(ingressGwRoutes, ruleInfo{
				nfRule: rule,
				table:  defaultIpTable,
				chain:  aclInputRulesChain,
				rule:   ruleSpec,
			})
		}
	}
	for _, rule := range ingressInfo.Rules {
		if !rule.Allow {
			continue
		}
		ruleSpec := []string{"-s", rule.SrcIP.String()}
		if rule.AllowedProtocol.String() != "" && rule.AllowedProtocol != models.ALL {
			ruleSpec = append(ruleSpec, "-p", rule.AllowedProtocol.String())
		}
		ruleSpec = append(ruleSpec, "-d", rule.DstIP.String())
		if len(rule.AllowedPorts) > 0 {
			ruleSpec = append(ruleSpec, "--dport",
				strings.Join(rule.AllowedPorts, ","))
		}
		ruleSpec = append(ruleSpec, "-j", "ACCEPT")
		ruleSpec = appendNetmakerCommentToRule(ruleSpec)
		n.deleteRule(defaultIpTable, aclInputRulesChain, genRuleKey(ruleSpec...))
		var nfRule *nftables.Rule
		if rule.SrcIP.IP.To4() != nil {
			e := []expr.Any{
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
			}
			if rule.AllowedProtocol.String() != "" && rule.AllowedProtocol != models.ALL {
				e = append(e, n.getExprForProto(rule.AllowedProtocol, true)...)
			}
			if len(rule.AllowedPorts) > 0 {
				e = append(e, n.getExprForPort(rule.AllowedPorts)...)
			}
			e = append(e, // Accept the packet
				&expr.Verdict{
					Kind: expr.VerdictAccept, // ACCEPT verdict
				})
			nfRule = &nftables.Rule{
				Table:    filterTable,
				Chain:    &nftables.Chain{Name: aclInputRulesChain},
				Exprs:    e,
				UserData: []byte(genRuleKey(ruleSpec...)), // Equivalent to the comment in iptables
			}

		} else {
			e := []expr.Any{
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
			}
			if rule.AllowedProtocol.String() != "" && rule.AllowedProtocol != models.ALL {
				e = append(e, n.getExprForProto(rule.AllowedProtocol, false)...)
			}
			if len(rule.AllowedPorts) > 0 {
				e = append(e, n.getExprForPort(rule.AllowedPorts)...)
			}
			e = append(e, // Accept the packet
				&expr.Verdict{
					Kind: expr.VerdictAccept, // ACCEPT verdict
				})
			nfRule = &nftables.Rule{
				Table:    filterTable,
				Chain:    &nftables.Chain{Name: aclInputRulesChain},
				Exprs:    e,
				UserData: []byte(genRuleKey(ruleSpec...)), // Equivalent to the comment in iptables
			}
		}
		n.conn.InsertRule(nfRule)
		if err := n.conn.Flush(); err != nil {
			logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
		} else {
			ingressGwRoutes = append(ingressGwRoutes, ruleInfo{
				nfRule: nfRule,
				table:  defaultIpTable,
				chain:  aclInputRulesChain,
				rule:   ruleSpec,
			})
		}

	}
	ingressRules.rulesMap[staticNodeRules] = ingressGwRoutes
	ingressRules.extraInfo = ingressInfo
	ruleTable[ingressInfo.IngressID] = ingressRules
	return nil
}
func (n *nftablesManager) GetSrcIpsExpr(ips []net.IPNet, isIpv4 bool) []expr.Any {
	var e []expr.Any
	if isIpv4 {

		for _, ip := range ips {
			// Match source IP
			e = append(e,
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       12, // Source IP offset in IPv4 header
					Len:          4,  // IPv4 address length
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask:           ip.Mask,
					Xor:            []byte{0, 0, 0, 0},
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     ip.IP.To4(),
				})
		}

	} else {
		for _, ip := range ips {
			e = append(e,
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       8,  // Source IP offset in IPv6 header
					Len:          16, // IPv6 address length
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            16,      // Length of the IPv6 address
					Mask:           ip.Mask, // Mask for /16
					Xor:            []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     ip.IP.To16(), // Replace with subnet prefix
				},
			)
		}
	}
	return e
}

func (n *nftablesManager) AddAclRules(server string, aclRules map[string]models.AclRule) {
	ruleTable := n.FetchRuleTable(server, aclTable)
	defer n.SaveRules(server, aclTable, ruleTable)
	n.mux.Lock()
	defer n.mux.Unlock()
	if ruleTable == nil {
		ruleTable = make(ruletable)
	}
	for _, aclRule := range aclRules {
		rules := []ruleInfo{}
		if _, ok := ruleTable[aclRule.ID]; !ok {
			ruleTable[aclRule.ID] = rulesCfg{
				rulesMap: make(map[string][]ruleInfo),
			}
		}
		if len(aclRule.IPList) > 0 {
			for _, ip := range aclRule.IPList {

				ruleSpec := []string{"-s", ip.String()}
				if aclRule.AllowedProtocol.String() != "" && aclRule.AllowedProtocol != models.ALL {
					ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
				}
				if len(aclRule.AllowedPorts) > 0 {
					ruleSpec = append(ruleSpec, "--dport",
						strings.Join(aclRule.AllowedPorts, ","))
				}
				ruleSpec = append(ruleSpec, "-j", "ACCEPT")
				ruleSpec = appendNetmakerCommentToRule(ruleSpec)
				n.deleteRule(defaultIpTable, aclInputRulesChain, genRuleKey(ruleSpec...))
				e := []expr.Any{}
				e = append(e, n.GetSrcIpsExpr([]net.IPNet{ip}, true)...)
				if aclRule.AllowedProtocol.String() != "" && aclRule.AllowedProtocol != models.ALL {
					e = append(e, n.getExprForProto(aclRule.AllowedProtocol, true)...)
				}
				if len(aclRule.AllowedPorts) > 0 {
					e = append(e, n.getExprForPort(aclRule.AllowedPorts)...)
				}

				e = append(e, // Accept the packet
					&expr.Verdict{
						Kind: expr.VerdictAccept, // ACCEPT verdict
					})
				nfRule := &nftables.Rule{
					Table:    filterTable,
					Chain:    &nftables.Chain{Name: aclInputRulesChain},
					Exprs:    e,
					UserData: []byte(genRuleKey(ruleSpec...)), // Equivalent to the comment in iptables
				}
				n.conn.InsertRule(nfRule)
				if err := n.conn.Flush(); err != nil {
					logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
				} else {
					rules = append(rules, ruleInfo{
						isIpv4: true,
						nfRule: nfRule,
						table:  defaultIpTable,
						chain:  aclInputRulesChain,
						rule:   ruleSpec,
					})

				}
			}

		}

		if len(aclRule.IP6List) > 0 {
			for _, ip := range aclRule.IP6List {
				ruleSpec := []string{"-s", ip.String()}
				if aclRule.AllowedProtocol.String() != "" && aclRule.AllowedProtocol != models.ALL {
					ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
				}
				if len(aclRule.AllowedPorts) > 0 {
					ruleSpec = append(ruleSpec, "--dport",
						strings.Join(aclRule.AllowedPorts, ","))
				}
				ruleSpec = append(ruleSpec, "-j", "ACCEPT")
				ruleSpec = appendNetmakerCommentToRule(ruleSpec)
				n.deleteRule(defaultIpTable, aclInputRulesChain, genRuleKey(ruleSpec...))
				e := []expr.Any{}
				e = append(e, n.GetSrcIpsExpr([]net.IPNet{ip}, false)...)
				if aclRule.AllowedProtocol.String() != "" && aclRule.AllowedProtocol != models.ALL {
					e = append(e, n.getExprForProto(aclRule.AllowedProtocol, false)...)
				}
				if len(aclRule.AllowedPorts) > 0 {
					e = append(e, n.getExprForPort(aclRule.AllowedPorts)...)
				}

				e = append(e, // Accept the packet
					&expr.Verdict{
						Kind: expr.VerdictAccept, // ACCEPT verdict
					})
				nfRule := &nftables.Rule{
					Table:    filterTable,
					Chain:    &nftables.Chain{Name: aclInputRulesChain},
					Exprs:    e,
					UserData: []byte(genRuleKey(ruleSpec...)), // Equivalent to the comment in iptables
				}
				n.conn.InsertRule(nfRule)
				if err := n.conn.Flush(); err != nil {
					logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
				} else {
					rules = append(rules, ruleInfo{
						isIpv4: false,
						nfRule: nfRule,
						table:  defaultIpTable,
						chain:  aclInputRulesChain,
						rule:   ruleSpec,
					})

				}
			}
		}
		if len(rules) > 0 {
			rCfg := rulesCfg{
				rulesMap: map[string][]ruleInfo{
					aclRule.ID: rules,
				},
				extraInfo: aclRule,
			}
			ruleTable[aclRule.ID] = rCfg
		}
	}
}

func (n *nftablesManager) UpsertAclRule(server string, aclRule models.AclRule) {
	ruleTable := n.FetchRuleTable(server, aclTable)
	defer n.SaveRules(server, aclTable, ruleTable)
	n.mux.Lock()
	defer n.mux.Unlock()
	ruleTable[aclRule.ID] = rulesCfg{
		rulesMap: make(map[string][]ruleInfo),
	}
	rules := []ruleInfo{}
	if _, ok := ruleTable[aclRule.ID]; !ok {
		ruleTable[aclRule.ID] = rulesCfg{
			rulesMap: make(map[string][]ruleInfo),
		}
	}
	if len(aclRule.IPList) > 0 {
		for _, ip := range aclRule.IPList {

			ruleSpec := []string{"-s", ip.String()}
			if aclRule.AllowedProtocol.String() != "" && aclRule.AllowedProtocol != models.ALL {
				ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
			}
			if len(aclRule.AllowedPorts) > 0 {
				ruleSpec = append(ruleSpec, "--dport",
					strings.Join(aclRule.AllowedPorts, ","))
			}
			ruleSpec = append(ruleSpec, "-j", "ACCEPT")
			ruleSpec = appendNetmakerCommentToRule(ruleSpec)
			n.deleteRule(defaultIpTable, aclInputRulesChain, genRuleKey(ruleSpec...))
			e := []expr.Any{}
			e = append(e, n.GetSrcIpsExpr([]net.IPNet{ip}, true)...)
			if aclRule.AllowedProtocol.String() != "" && aclRule.AllowedProtocol != models.ALL {
				e = append(e, n.getExprForProto(aclRule.AllowedProtocol, true)...)
			}
			if len(aclRule.AllowedPorts) > 0 {
				e = append(e, n.getExprForPort(aclRule.AllowedPorts)...)
			}

			e = append(e, // Accept the packet
				&expr.Verdict{
					Kind: expr.VerdictAccept, // ACCEPT verdict
				})
			nfRule := &nftables.Rule{
				Table:    filterTable,
				Chain:    &nftables.Chain{Name: aclInputRulesChain},
				Exprs:    e,
				UserData: []byte(genRuleKey(ruleSpec...)), // Equivalent to the comment in iptables
			}
			n.conn.InsertRule(nfRule)
			if err := n.conn.Flush(); err != nil {
				logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
			} else {
				rules = append(rules, ruleInfo{
					isIpv4: true,
					nfRule: nfRule,
					table:  defaultIpTable,
					chain:  aclInputRulesChain,
					rule:   ruleSpec,
				})

			}
		}

	}

	if len(aclRule.IP6List) > 0 {
		for _, ip := range aclRule.IP6List {

			ruleSpec := []string{"-s", ip.String()}
			if aclRule.AllowedProtocol.String() != "" && aclRule.AllowedProtocol != models.ALL {
				ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
			}
			if len(aclRule.AllowedPorts) > 0 {
				ruleSpec = append(ruleSpec, "--dport",
					strings.Join(aclRule.AllowedPorts, ","))
			}
			ruleSpec = append(ruleSpec, "-j", "ACCEPT")
			ruleSpec = appendNetmakerCommentToRule(ruleSpec)
			n.deleteRule(defaultIpTable, aclInputRulesChain, genRuleKey(ruleSpec...))
			e := []expr.Any{}
			e = append(e, n.GetSrcIpsExpr([]net.IPNet{ip}, false)...)
			if aclRule.AllowedProtocol.String() != "" && aclRule.AllowedProtocol != models.ALL {
				e = append(e, n.getExprForProto(aclRule.AllowedProtocol, false)...)
			}
			if len(aclRule.AllowedPorts) > 0 {
				e = append(e, n.getExprForPort(aclRule.AllowedPorts)...)
			}

			e = append(e, // Accept the packet
				&expr.Verdict{
					Kind: expr.VerdictAccept, // ACCEPT verdict
				})
			nfRule := &nftables.Rule{
				Table:    filterTable,
				Chain:    &nftables.Chain{Name: aclInputRulesChain},
				Exprs:    e,
				UserData: []byte(genRuleKey(ruleSpec...)), // Equivalent to the comment in iptables
			}
			n.conn.InsertRule(nfRule)
			if err := n.conn.Flush(); err != nil {
				logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
			} else {
				rules = append(rules, ruleInfo{
					isIpv4: false,
					nfRule: nfRule,
					table:  defaultIpTable,
					chain:  aclInputRulesChain,
					rule:   ruleSpec,
				})

			}
		}
	}

	if len(rules) > 0 {
		rCfg := rulesCfg{
			rulesMap: map[string][]ruleInfo{
				aclRule.ID: rules,
			},
			extraInfo: aclRule,
		}
		ruleTable[aclRule.ID] = rCfg
	}

}

func (n *nftablesManager) DeleteAclRule(server, aclID string) {
	ruleTable := n.FetchRuleTable(server, aclTable)
	defer n.SaveRules(server, aclTable, ruleTable)
	n.mux.Lock()
	defer n.mux.Unlock()
	rulesCfg, ok := ruleTable[aclID]
	if !ok {
		return
	}
	rules := rulesCfg.rulesMap[aclID]
	for _, rule := range rules {
		n.deleteRule(rule.table, rule.chain, genRuleKey(rule.rule...))
	}
	n.conn.Flush()
	delete(ruleTable, aclID)
}
func (n *nftablesManager) ChangeACLFwdTarget(target string) {
	// check if rule exists with current target
	v := &expr.Verdict{
		Kind: expr.VerdictAccept,
	}
	if target == targetDrop {
		v = &expr.Verdict{
			Kind: expr.VerdictDrop,
		}
	}

	newRule := &nftables.Rule{
		Table: filterTable,
		Chain: &nftables.Chain{Name: aclFwdRulesChain},
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
			},
			&expr.Counter{},
			v,
		},
		UserData: []byte(genRuleKey("-i", ncutils.GetInterfaceName(), "-j", target)),
	}
	if n.ruleExists(newRule) {
		return
	}
	slog.Info("setting acl input chain target to", "target", target)
	// delete old target and insert new rule
	oldVerdict := &expr.Verdict{
		Kind: expr.VerdictAccept,
	}
	oldTarget := targetAccept
	if target == targetAccept {
		oldVerdict = &expr.Verdict{
			Kind: expr.VerdictDrop,
		}
		oldTarget = targetDrop
	}
	oldRule := &nftables.Rule{
		Table: filterTable,
		Chain: &nftables.Chain{Name: aclFwdRulesChain},
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
			},
			&expr.Counter{},
			oldVerdict,
		},
		UserData: []byte(genRuleKey("-i", ncutils.GetInterfaceName(), "-j", oldTarget)),
	}
	rules, err := n.conn.GetRules(newRule.Table, newRule.Chain)
	if err != nil {
		slog.Error("Error fetching rules: %v", err.Error())
	}
	for _, rI := range rules {
		if rulesEqual(rI, oldRule) {
			logger.Log(0, "DELETING OLD TARGET ", oldTarget)
			err = n.conn.DelRule(rI)
			if err != nil {
				logger.Log(0, "failed to delete old target ", err.Error())
			}
			break
		}
	}

	n.conn.InsertRule(newRule)
	// Apply the changes
	if err := n.conn.Flush(); err != nil {
		logger.Log(0, "Error Changing ACL TArget: %v\n", err.Error())
	}
}

func (n *nftablesManager) AddAclEgressRules(server string, aclRules map[string]models.AclRule) {}
func (n *nftablesManager) DeleteAclEgressRule(server, aclID string)                            {}
func (n *nftablesManager) UpsertAclEgressRule(server string, aclRule models.AclRule)           {}

func (n *nftablesManager) ChangeACLInTarget(target string) {
	// check if rule exists with current target
	v := &expr.Verdict{
		Kind: expr.VerdictAccept,
	}
	if target == targetDrop {
		v = &expr.Verdict{
			Kind: expr.VerdictDrop,
		}
	}

	newRule := &nftables.Rule{
		Table: filterTable,
		Chain: &nftables.Chain{Name: aclInputRulesChain},
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
			},
			&expr.Counter{},
			v,
		},
		UserData: []byte(genRuleKey("-i", ncutils.GetInterfaceName(), "-j", target)),
	}
	if n.ruleExists(newRule) {
		return
	}
	slog.Info("setting acl input chain target to", "target", target)
	// delete old target and insert new rule
	oldVerdict := &expr.Verdict{
		Kind: expr.VerdictAccept,
	}
	oldTarget := targetAccept
	if target == targetAccept {
		oldVerdict = &expr.Verdict{
			Kind: expr.VerdictDrop,
		}
		oldTarget = targetDrop
	}
	oldRule := &nftables.Rule{
		Table: filterTable,
		Chain: &nftables.Chain{Name: aclInputRulesChain},
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
			},
			&expr.Counter{},
			oldVerdict,
		},
		UserData: []byte(genRuleKey("-i", ncutils.GetInterfaceName(), "-j", oldTarget)),
	}
	rules, err := n.conn.GetRules(newRule.Table, newRule.Chain)
	if err != nil {
		slog.Error("Error fetching rules: %v", err.Error())
	}
	for _, rI := range rules {
		if rulesEqual(rI, oldRule) {
			logger.Log(0, "DELETING OLD TARGET ", oldTarget)
			err = n.conn.DelRule(rI)
			if err != nil {
				logger.Log(0, "failed to delete old target ", err.Error())
			}
			break
		}
	}

	n.conn.InsertRule(newRule)
	// Apply the changes
	if err := n.conn.Flush(); err != nil {
		logger.Log(0, "Error Changing ACL TArget: %v\n", err.Error())
	}
}

func (n *nftablesManager) ruleExists(r *nftables.Rule) bool {
	rules, err := n.conn.GetRules(r.Table, r.Chain)
	if err != nil {
		return false
	}
	for _, rule := range rules {
		if rulesEqual(r, rule) {
			return true
		}
	}
	return false
}

// rulesEqual checks if two rules are equivalent
func rulesEqual(rule1, rule2 *nftables.Rule) bool {
	if len(rule1.Exprs) != len(rule2.Exprs) {
		return false
	}
	if string(rule1.UserData) == string(rule2.UserData) {
		return true
	}

	return false
}
