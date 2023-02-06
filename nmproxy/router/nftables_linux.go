package router

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/sys/unix"
)

// constants needed to create nftable rules
const (
	ipv4Len        = 4
	ipv4SrcOffset  = 12
	ipv4DestOffset = 16
	ipv6Len        = 16
	ipv6SrcOffset  = 8
	ipv6DestOffset = 24
)

type nftablesManager struct {
	conn     *nftables.Conn
	ingRules serverrulestable
	mux      sync.Mutex
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
					&expr.Verdict{Kind: expr.VerdictDrop},
				},
				UserData: []byte(genRuleKey("-i", ncutils.GetInterfaceName(), "-j", "DROP")),
			},
			rule:  []string{"-i", ncutils.GetInterfaceName(), "-j", "DROP"},
			table: defaultIpTable,
			chain: netmakerFilterChain,
		},
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
					&expr.Verdict{Kind: expr.VerdictReturn},
				},
				UserData: []byte(genRuleKey("-i", ncutils.GetInterfaceName(), "-j", "RETURN")),
			},
			rule:  []string{"-i", ncutils.GetInterfaceName(), "-j", "RETURN"},
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

// CreateChains - creates default chains and rules
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
	*defaultForwardPolicy = nftables.ChainPolicyDrop

	forwardChain := &nftables.Chain{
		Name:     iptableFWDChain,
		Table:    filterTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   defaultForwardPolicy,
	}
	n.conn.AddChain(forwardChain)

	postroutingChain := &nftables.Chain{
		Name:     nattablePRTChain,
		Table:    natTable,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	}
	n.conn.AddChain(postroutingChain)

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

// CleanRoutingRules cleans existing iptables resources that we created by the agent
func (n *nftablesManager) CleanRoutingRules(server, ruleTableName string) {
	n.conn.ListTables()
	ruleTable := n.FetchRuleTable(server, ruleTableName)
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

func (n *nftablesManager) DeleteRuleTable(server, ruleTableName string) {
}
func (n *nftablesManager) InsertEgressRoutingRules(server string, egressInfo models.EgressInfo) error {
	return nil
}
func (n *nftablesManager) AddEgressRoutingRule(server string, egressInfo models.EgressInfo, peerInfo models.PeerRouteInfo) error {
	return nil
}

// AddIngressRoutingRule - adds a ingress route for a peer
func (n *nftablesManager) AddIngressRoutingRule(server, extPeerKey string, peerInfo models.PeerRouteInfo) error {
	ruleTable := n.FetchRuleTable(server, ingressTable)
	defer n.SaveRules(server, ingressTable, ruleTable)
	n.mux.Lock()
	defer n.mux.Unlock()
	prefix, err := netip.ParsePrefix(peerInfo.PeerAddr.String())
	if err != nil {
		return err
	}
	peerIP, _, err := net.ParseCIDR(peerInfo.PeerAddr.String())
	if err != nil {
		return err
	}
	ruleSpec := []string{"-d", peerInfo.PeerAddr.String(), "-j", "ACCEPT"}
	var rule *nftables.Rule
	if prefix.Addr().Unmap().Is6() {
		// ipv6 rule
		rule = &nftables.Rule{
			Table:    filterTable,
			Chain:    &nftables.Chain{Name: netmakerFilterChain, Table: filterTable},
			UserData: []byte(genRuleKey(ruleSpec...)),
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       ipv6DestOffset,
					Len:          ipv6Len,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     peerIP.To16(),
				},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		}
	} else {
		// ipv4 rule
		rule = &nftables.Rule{
			Table:    filterTable,
			Chain:    &nftables.Chain{Name: netmakerFilterChain, Table: filterTable},
			UserData: []byte(genRuleKey(ruleSpec...)),
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       ipv4DestOffset,
					Len:          ipv4Len,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     peerIP.To4(),
				},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		}
	}
	rule.Position = 1
	n.conn.InsertRule(rule)
	if err := n.conn.Flush(); err != nil {
		logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
	}
	ruleTable[extPeerKey].rulesMap[peerInfo.PeerKey] = []ruleInfo{
		{
			nfRule: rule,
			rule:   ruleSpec,
			chain:  netmakerFilterChain,
			table:  defaultIpTable,
		},
	}
	return nil
}

// InsertIngressRoutingRules inserts an iptables rules for an ext. client to the netmaker chain and if enabled, to the nat chain
func (n *nftablesManager) InsertIngressRoutingRules(server string, extinfo models.ExtClientInfo) error {
	ruleTable := n.FetchRuleTable(server, ingressTable)
	defer n.SaveRules(server, ingressTable, ruleTable)
	n.mux.Lock()
	defer n.mux.Unlock()
	logger.Log(0, "Adding Ingress Rules For Ext. Client: ", extinfo.ExtPeerKey)
	prefix, err := netip.ParsePrefix(extinfo.ExtPeerAddr.String())
	if err != nil {
		return err
	}
	extPeerIP, _, err := net.ParseCIDR(extinfo.ExtPeerAddr.String())
	if err != nil {
		return err
	}
	ingwIP, _, err := net.ParseCIDR(extinfo.IngGwAddr.String())
	if err != nil {
		return err
	}
	var (
		ruleSpec = []string{"-s", extinfo.ExtPeerAddr.String(), "!", "-d",
			extinfo.IngGwAddr.String(), "-j", netmakerFilterChain}
		rule   *nftables.Rule
		isIpv4 = true
	)
	if prefix.Addr().Unmap().Is6() {
		isIpv4 = false
		rule = &nftables.Rule{
			Table:    filterTable,
			Chain:    &nftables.Chain{Name: iptableFWDChain, Table: filterTable},
			UserData: []byte(genRuleKey(ruleSpec...)),
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       ipv6SrcOffset,
					Len:          ipv6Len,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     extPeerIP.To16(),
				},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       ipv6DestOffset,
					Len:          ipv6Len,
				},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     ingwIP.To16(),
				},
				&expr.Verdict{Kind: expr.VerdictJump, Chain: netmakerFilterChain},
			},
		}
	} else {
		rule = &nftables.Rule{
			Table:    filterTable,
			Chain:    &nftables.Chain{Name: iptableFWDChain, Table: filterTable},
			UserData: []byte(genRuleKey(ruleSpec...)),
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       ipv4SrcOffset,
					Len:          ipv4Len,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     extPeerIP.To4(),
				},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       ipv4DestOffset,
					Len:          ipv4Len,
				},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     ingwIP.To4(),
				},
				&expr.Verdict{Kind: expr.VerdictJump, Chain: netmakerFilterChain},
			},
		}
	}
	ruleTable[extinfo.ExtPeerKey] = rulesCfg{
		isIpv4:   isIpv4,
		rulesMap: make(map[string][]ruleInfo),
	}
	logger.Log(0, fmt.Sprintf("-----> adding rule: %+v", ruleSpec))
	rule.Position = 1
	n.conn.InsertRule(rule)
	if err := n.conn.Flush(); err != nil {
		logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
	}
	fwdJumpRule := ruleInfo{
		nfRule: rule,
		rule:   ruleSpec,
		chain:  iptableFWDChain,
		table:  defaultIpTable,
	}
	nfJumpRules = append(nfJumpRules, fwdJumpRule)

	ruleSpec = []string{"-d", extinfo.ExtPeerAddr.String(), "-j", "ACCEPT"}
	if isIpv4 {
		rule = &nftables.Rule{
			Table:    filterTable,
			Chain:    &nftables.Chain{Name: netmakerFilterChain, Table: filterTable},
			UserData: []byte(genRuleKey(ruleSpec...)),
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       ipv4DestOffset,
					Len:          ipv4Len,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     extPeerIP.To4(),
				},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		}
	} else {
		rule = &nftables.Rule{
			Table:    filterTable,
			Chain:    &nftables.Chain{Name: netmakerFilterChain, Table: filterTable},
			UserData: []byte(genRuleKey(ruleSpec...)),
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       ipv6DestOffset,
					Len:          ipv6Len,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     extPeerIP.To16(),
				},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		}
	}
	logger.Log(0, fmt.Sprintf("-----> adding rule: %+v", ruleSpec))
	rule.Position = 1
	n.conn.InsertRule(rule)
	if err := n.conn.Flush(); err != nil {
		logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
	}
	ruleTable[extinfo.ExtPeerKey].rulesMap[extinfo.ExtPeerKey] = []ruleInfo{
		fwdJumpRule,
		{
			nfRule: rule,
			rule:   ruleSpec,
			chain:  netmakerFilterChain,
			table:  defaultIpTable,
		},
	}
	for _, peerInfo := range extinfo.Peers {
		if !peerInfo.Allow {
			continue
		}
		peerIP, _, err := net.ParseCIDR(extinfo.IngGwAddr.String())
		if err != nil {
			logger.Log(0, "Error parsing peer IP CIDR: ", err.Error())
			continue
		}
		ruleSpec := []string{"-s", extinfo.ExtPeerAddr.String(), "-d", peerInfo.PeerAddr.String(), "-j", "ACCEPT"}
		if isIpv4 {
			rule = &nftables.Rule{
				Table:    filterTable,
				Chain:    &nftables.Chain{Name: netmakerFilterChain, Table: filterTable},
				UserData: []byte(genRuleKey(ruleSpec...)),
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       ipv4SrcOffset,
						Len:          ipv4Len,
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     extPeerIP.To4(),
					},
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       ipv4DestOffset,
						Len:          ipv4Len,
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     peerIP.To4(),
					},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			}
		} else {
			rule = &nftables.Rule{
				Table:    filterTable,
				Chain:    &nftables.Chain{Name: netmakerFilterChain, Table: filterTable},
				UserData: []byte(genRuleKey(ruleSpec...)),
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       ipv6SrcOffset,
						Len:          ipv6Len,
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     extPeerIP.To16(),
					},
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       ipv6DestOffset,
						Len:          ipv6Len,
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     peerIP.To16(),
					},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			}
		}
		logger.Log(0, fmt.Sprintf("-----> adding rule: %+v", ruleSpec))
		rule.Position = 1
		n.conn.InsertRule(rule)
		if err := n.conn.Flush(); err != nil {
			logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
			continue
		}
		ruleTable[extinfo.ExtPeerKey].rulesMap[peerInfo.PeerKey] = []ruleInfo{
			{
				nfRule: rule,
				rule:   ruleSpec,
				chain:  netmakerFilterChain,
				table:  defaultIpTable,
			},
		}
	}
	if !extinfo.Masquerade {
		return nil
	}
	routes := ruleTable[extinfo.ExtPeerKey].rulesMap[extinfo.ExtPeerKey]
	ruleSpec = []string{"-s", extinfo.ExtPeerAddr.String(), "-o", ncutils.GetInterfaceName(), "-j", "MASQUERADE"}
	logger.Log(0, fmt.Sprintf("----->[NAT] adding rule: %+v", ruleSpec))
	if isIpv4 {
		rule = &nftables.Rule{
			Table:    natTable,
			Chain:    &nftables.Chain{Name: netmakerNatChain, Table: natTable},
			UserData: []byte(genRuleKey(ruleSpec...)),
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       ipv4SrcOffset,
					Len:          ipv4Len,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     extPeerIP.To4(),
				},
				&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
				},
				&expr.Masq{},
			},
		}
	} else {
		rule = &nftables.Rule{
			Table:    natTable,
			Chain:    &nftables.Chain{Name: netmakerNatChain, Table: natTable},
			UserData: []byte(genRuleKey(ruleSpec...)),
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       ipv6SrcOffset,
					Len:          ipv6Len,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     extPeerIP.To16(),
				},
				&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
				},
				&expr.Masq{},
			},
		}
	}
	rule.Position = 1
	n.conn.InsertRule(rule)
	if err := n.conn.Flush(); err != nil {
		logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
	} else {
		routes = append(routes, ruleInfo{
			nfRule: rule,
			rule:   ruleSpec,
			table:  defaultNatTable,
			chain:  netmakerNatChain,
		})
	}

	ruleSpec = []string{"-d", extinfo.ExtPeerAddr.String(), "-o", ncutils.GetInterfaceName(), "-j", "MASQUERADE"}
	logger.Log(0, fmt.Sprintf("----->[NAT] adding rule: %+v", ruleSpec))
	if isIpv4 {
		rule = &nftables.Rule{
			Table:    natTable,
			Chain:    &nftables.Chain{Name: netmakerNatChain, Table: natTable},
			UserData: []byte(genRuleKey(ruleSpec...)),
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       ipv4DestOffset,
					Len:          ipv4Len,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     extPeerIP.To4(),
				},
				&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
				},
				&expr.Masq{},
			},
		}
	} else {
		rule = &nftables.Rule{
			Table:    natTable,
			Chain:    &nftables.Chain{Name: netmakerNatChain, Table: natTable},
			UserData: []byte(genRuleKey(ruleSpec...)),
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       ipv6DestOffset,
					Len:          ipv6Len,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     extPeerIP.To16(),
				},
				&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte(ncutils.GetInterfaceName() + "\x00"),
				},
				&expr.Masq{},
			},
		}
	}
	rule.Position = 1
	n.conn.InsertRule(rule)
	if err := n.conn.Flush(); err != nil {
		logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
	} else {
		routes = append(routes, ruleInfo{
			nfRule: rule,
			rule:   ruleSpec,
			table:  defaultNatTable,
			chain:  netmakerNatChain,
		})
	}

	ruleTable[extinfo.ExtPeerKey].rulesMap[extinfo.ExtPeerKey] = routes

	return nil
}

// FetchRuleTable - fetches the rule table by table name
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
	}
	return rules
}

// SaveRules - saves the rule table by tablename
func (n *nftablesManager) SaveRules(server, tableName string, rules ruletable) {
	n.mux.Lock()
	defer n.mux.Unlock()
	logger.Log(0, "Saving rules to table: ", tableName)
	switch tableName {
	case ingressTable:
		n.ingRules[server] = rules
	}
}

// RemoveRoutingRules removes an iptables rules related to a peer
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
				return fmt.Errorf("iptables: error while removing existing %s rules [%v] for %s: %v",
					rule.table, rule.rule, peerKey, err)
			}
		}
	}
	delete(rulesTable, peerKey)
	return nil
}

// DeleteRoutingRule - removes an iptables rule pair from forwarding and nat chains
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
				return fmt.Errorf("iptables: error while removing existing %s rules [%v] for %s: %v",
					rule.table, rule.rule, srcPeerKey, err)
			}
		}
	} else {
		return errors.New("rules not found for: " + dstPeerKey)
	}
	return nil
}

// FlushAll - removes all the rules added by netmaker and deletes the netmaker chains
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
