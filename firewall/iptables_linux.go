package firewall

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"

	"golang.org/x/exp/slog"

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
	iptableINChain      = "INPUT"
	nattablePRTChain    = "POSTROUTING"
	netmakerSignature   = "NETMAKER"
	aclInputRulesChain  = "NETMAKER-ACL-IN"
	aclFwdRulesChain    = "NETMAKER-ACL-FWD"
	aclOutputRulesChain = "NETMAKER-ACL-OUT"
)

type iptablesManager struct {
	ipv4Client   *iptables.IPTables
	ipv6Client   *iptables.IPTables
	ingRules     serverrulestable
	engressRules serverrulestable
	aclRules     serverrulestable
	mux          sync.Mutex
}

var (
	aclInChainDropRule = ruleInfo{
		rule: []string{"-i", ncutils.GetInterfaceName(), "-m",
			"comment", "--comment", netmakerSignature, "-j", "DROP"},
		table: defaultIpTable,
		chain: aclInputRulesChain,
	}
	aclFwdChainDropRule = ruleInfo{
		rule: []string{"-i", ncutils.GetInterfaceName(), "-m",
			"comment", "--comment", netmakerSignature, "-j", "DROP"},
		table: defaultIpTable,
		chain: aclFwdRulesChain,
	}
	dropRules = []ruleInfo{
		{
			rule: []string{"-i", ncutils.GetInterfaceName(), "-m", "comment",
				"--comment", netmakerSignature, "-j", "RETURN"},
			table: defaultIpTable,
			chain: netmakerFilterChain,
		},
		aclInChainDropRule,
		aclFwdChainDropRule,
	}

	// filter table netmaker jump rules
	filterNmJumpRules = []ruleInfo{
		//iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
		{
			rule: []string{"-i", ncutils.GetInterfaceName(), "-m", "conntrack",
				"--ctstate", "ESTABLISHED,RELATED", "-m", "comment",
				"--comment", netmakerSignature, "-j", "ACCEPT"},
			table: defaultIpTable,
			chain: iptableINChain,
		},
		{
			rule: []string{"-i", ncutils.GetInterfaceName(), "-j", aclInputRulesChain,
				"-m", "comment", "--comment", netmakerSignature},
			table: defaultIpTable,
			chain: iptableINChain,
		},
		{
			rule: []string{"-i", ncutils.GetInterfaceName(), "-m", "conntrack",
				"--ctstate", "ESTABLISHED,RELATED", "-m", "comment",
				"--comment", netmakerSignature, "-j", "ACCEPT"},
			table: defaultIpTable,
			chain: iptableFWDChain,
		},
		{
			rule: []string{"-o", ncutils.GetInterfaceName(), "-m", "conntrack",
				"--ctstate", "ESTABLISHED,RELATED", "-m", "comment",
				"--comment", netmakerSignature, "-j", "ACCEPT"},
			table: defaultIpTable,
			chain: iptableFWDChain,
		},
		{
			rule: []string{"-i", ncutils.GetInterfaceName(), "!", "-o", ncutils.GetInterfaceName(), "-j", aclFwdRulesChain,
				"-m", "comment", "--comment", netmakerSignature},
			table: defaultIpTable,
			chain: iptableFWDChain,
		},
		{
			rule: []string{"-i", ncutils.GetInterfaceName(), "-o", ncutils.GetInterfaceName(), "-j", aclInputRulesChain,
				"-m", "comment", "--comment", netmakerSignature},
			table: defaultIpTable,
			chain: iptableFWDChain,
		},
		{
			rule:  []string{"-m", "comment", "--comment", netmakerSignature, "-j", "ACCEPT"},
			table: defaultIpTable,
			chain: aclOutputRulesChain,
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

func (i *iptablesManager) ChangeACLInTarget(target string) {

	ruleSpec := aclInChainDropRule.rule
	table := aclInChainDropRule.table
	chain := aclInChainDropRule.chain
	ruleSpec[len(ruleSpec)-1] = target
	ok4, _ := i.ipv4Client.Exists(table, chain, ruleSpec...)
	ok6, _ := i.ipv6Client.Exists(table, chain, ruleSpec...)
	if ok4 && ok6 {
		return
	}
	slog.Debug("setting acl input chain target to", "target", target)
	if target == targetAccept {

		// remove any DROP rule
		ruleSpec[len(ruleSpec)-1] = targetDrop
		i.ipv4Client.DeleteIfExists(table, chain, ruleSpec...)
		i.ipv6Client.DeleteIfExists(table, chain, ruleSpec...)
		// Add ACCEPT RULE
		ruleSpec[len(ruleSpec)-1] = targetAccept
		i.ipv4Client.Append(table, chain, ruleSpec...)
		i.ipv6Client.Append(table, chain, ruleSpec...)
	} else {
		// remove any ACCEPT rule
		ruleSpec[len(ruleSpec)-1] = targetAccept
		i.ipv4Client.DeleteIfExists(table, chain, ruleSpec...)
		i.ipv6Client.DeleteIfExists(table, chain, ruleSpec...)
		// Add DROP RULE
		ruleSpec[len(ruleSpec)-1] = targetDrop
		i.ipv4Client.Append(table, chain, ruleSpec...)
		i.ipv6Client.Append(table, chain, ruleSpec...)
	}
}

func (i *iptablesManager) ChangeACLFwdTarget(target string) {

	ruleSpec := aclFwdChainDropRule.rule
	table := aclFwdChainDropRule.table
	chain := aclFwdChainDropRule.chain
	ruleSpec[len(ruleSpec)-1] = target
	ok4, _ := i.ipv4Client.Exists(table, chain, ruleSpec...)
	ok6, _ := i.ipv6Client.Exists(table, chain, ruleSpec...)
	if ok4 && ok6 {
		return
	}
	slog.Debug("setting acl forward chain target to", "target", target)
	if target == targetAccept {

		// remove any DROP rule
		ruleSpec[len(ruleSpec)-1] = targetDrop
		i.ipv4Client.DeleteIfExists(table, chain, ruleSpec...)
		i.ipv6Client.DeleteIfExists(table, chain, ruleSpec...)
		// Add ACCEPT RULE
		ruleSpec[len(ruleSpec)-1] = targetAccept
		i.ipv4Client.Append(table, chain, ruleSpec...)
		i.ipv6Client.Append(table, chain, ruleSpec...)
	} else {
		// remove any ACCEPT rule
		ruleSpec[len(ruleSpec)-1] = targetAccept
		i.ipv4Client.DeleteIfExists(table, chain, ruleSpec...)
		i.ipv6Client.DeleteIfExists(table, chain, ruleSpec...)
		// Add DROP RULE
		ruleSpec[len(ruleSpec)-1] = targetDrop
		i.ipv4Client.Append(table, chain, ruleSpec...)
		i.ipv6Client.Append(table, chain, ruleSpec...)
	}
}

// iptablesManager.ForwardRule inserts forwarding rules
func (i *iptablesManager) ForwardRule() error {
	i.mux.Lock()
	defer i.mux.Unlock()
	logger.Log(0, "adding forwarding rule")

	// Set the policy To accept on forward chain
	i.ipv4Client.ChangePolicy(defaultIpTable, iptableFWDChain, "ACCEPT")
	i.ipv6Client.ChangePolicy(defaultIpTable, iptableFWDChain, "ACCEPT")
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
			for _, rule := range rules {
				err := i.ipv4Client.DeleteIfExists(rule.table, rule.chain, rule.rule...)
				if err != nil {
					logger.Log(1, fmt.Sprintf("failed to delete rule [%s]: %+v, Err: %s", key, rule, err.Error()))
				}
				err = i.ipv6Client.DeleteIfExists(rule.table, rule.chain, rule.rule...)
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
	err = createChain(i.ipv4Client, defaultIpTable, aclInputRulesChain)
	if err != nil {
		logger.Log(1, "failed to create netmaker chain: ", err.Error())
		return err
	}
	err = createChain(i.ipv4Client, defaultIpTable, aclFwdRulesChain)
	if err != nil {
		logger.Log(1, "failed to create netmaker chain: ", err.Error())
		return err
	}
	err = createChain(i.ipv4Client, defaultIpTable, aclOutputRulesChain)
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
	err = createChain(i.ipv6Client, defaultIpTable, aclInputRulesChain)
	if err != nil {
		logger.Log(1, "failed to create netmaker chain: ", err.Error())
		return err
	}
	err = createChain(i.ipv6Client, defaultIpTable, aclFwdRulesChain)
	if err != nil {
		logger.Log(1, "failed to create netmaker chain: ", err.Error())
		return err
	}
	err = createChain(i.ipv6Client, defaultIpTable, aclOutputRulesChain)
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
	// add metrics rule
	server := config.GetServer(config.CurrServer)
	if server != nil {
		port := server.MetricsPort
		rule := ruleInfo{
			rule: []string{"-i", ncutils.GetInterfaceName(), "-p", "tcp", "--dport", fmt.Sprint(port), "-m", "comment",
				"--comment", netmakerSignature, "-j", "ACCEPT"},
			table: defaultIpTable,
			chain: aclInputRulesChain,
		}
		err := i.ipv4Client.Insert(rule.table, rule.chain, 1, rule.rule...)
		if err != nil {
			logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", rule.rule, err.Error()))
		}
		err = i.ipv6Client.Insert(rule.table, rule.chain, 1, rule.rule...)
		if err != nil {
			logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", rule.rule, err.Error()))
		}
	}

	i.AddDropRules(dropRules)

}

func (i *iptablesManager) removeJumpRules() {
	rules, err := i.ipv4Client.List(defaultIpTable, iptableFWDChain)
	if err == nil {
		for _, rule := range rules {
			if containsComment(rule, netmakerSignature) {
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
			if containsComment(rule, netmakerSignature) {
				err := i.ipv6Client.Delete(defaultIpTable, iptableFWDChain, strings.Fields(rule)[2:]...)
				if err != nil {
					logger.Log(1, "failed to delete rule: ", rule, err.Error())
				}
			}
		}
	}

	rules, err = i.ipv4Client.List(defaultIpTable, iptableINChain)
	if err == nil {
		for _, rule := range rules {
			if containsComment(rule, netmakerSignature) {
				err := i.ipv4Client.Delete(defaultIpTable, iptableINChain, strings.Fields(rule)[2:]...)
				if err != nil {
					logger.Log(1, "failed to delete rule: ", rule, err.Error())
				}
			}
		}
	}
	rules, err = i.ipv6Client.List(defaultIpTable, iptableINChain)
	if err == nil {
		for _, rule := range rules {
			if containsComment(rule, netmakerSignature) {
				err := i.ipv6Client.Delete(defaultIpTable, iptableINChain, strings.Fields(rule)[2:]...)
				if err != nil {
					logger.Log(1, "failed to delete rule: ", rule, err.Error())
				}
			}
		}
	}
	rules, err = i.ipv4Client.List(defaultNatTable, nattablePRTChain)
	if err == nil {
		for _, rule := range rules {
			if containsComment(rule, netmakerSignature) {
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
			if containsComment(rule, netmakerSignature) {
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
	ruleTable[egressInfo.EgressID] = rulesCfg{
		rulesMap:  make(map[string][]ruleInfo),
		extraInfo: egressInfo.EgressGWCfg,
	}
	egressGwRoutes := []ruleInfo{}
	for _, egressGwRange := range egressInfo.EgressGWCfg.RangesWithMetric {
		if egressGwRange.Nat {
			iptablesClient := i.ipv4Client
			source := egressInfo.Network.String()
			if !isAddrIpv4(egressGwRange.Network) {
				iptablesClient = i.ipv6Client
				source = egressInfo.Network6.String()
			}
			egressRangeIface, err := getInterfaceName(config.ToIPNet(egressGwRange.Network))
			if err != nil {
				logger.Log(0, "failed to get interface name: ", egressRangeIface, err.Error())
			} else {
				ruleSpec := []string{"-s", source, "-o", egressRangeIface, "-j", "MASQUERADE"}
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

func (i *iptablesManager) AddDropRules(dropRules []ruleInfo) {
	for _, dropRule := range dropRules {
		// create drop rule in netmakefilterchain
		ok, err := i.ipv4Client.Exists(dropRule.table, dropRule.chain, dropRule.rule...)
		if err == nil && !ok {
			if err := i.ipv4Client.Append(dropRule.table,
				dropRule.chain, dropRule.rule...); err != nil {
				logger.Log(1, fmt.Sprintf("failed to add rule: %v Err: %v",
					dropRule, err.Error()))
			}
		}
		ok, err = i.ipv6Client.Exists(dropRule.table, dropRule.chain, dropRule.rule...)
		if err == nil && !ok {
			if err := i.ipv6Client.Append(dropRule.table,
				dropRule.chain, dropRule.rule...); err != nil {
				logger.Log(1, fmt.Sprintf("failed to add rule: %v Err: %v",
					dropRule, err.Error()))
			}
		}
	}
}

func (i *iptablesManager) InsertIngressRoutingRules(server string, ingressInfo models.IngressInfo) error {
	ruleTable := i.FetchRuleTable(server, ingressTable)
	defer i.SaveRules(server, ingressTable, ruleTable)
	i.mux.Lock()
	defer i.mux.Unlock()
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

		iptablesClient := i.ipv4Client
		v4 := true
		if ip.To4() == nil {
			iptablesClient = i.ipv6Client
			v4 = false
		}
		cnt := i.getLastRuleCnt(defaultIpTable, aclInputRulesChain, v4)
		cnt--
		if cnt <= 0 {
			cnt = 1
		}
		ruleSpec := []string{"-s", ip.String(), "-j", targetDrop}
		ruleSpec = appendNetmakerCommentToRule(ruleSpec)
		err := iptablesClient.InsertUnique(defaultIpTable, aclInputRulesChain,
			cnt, ruleSpec...)
		if err != nil {
			logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
		} else {
			ingressGwRoutes = append(ingressGwRoutes, ruleInfo{
				table: defaultIpTable,
				chain: aclInputRulesChain,
				rule:  ruleSpec,
			})
		}
		cnt = i.getLastRuleCnt(defaultIpTable, aclInputRulesChain, v4)
		cnt--
		if cnt <= 0 {
			cnt = 1
		}
		ruleSpec = []string{"-d", ip.String(), "-j", targetDrop}
		ruleSpec = appendNetmakerCommentToRule(ruleSpec)
		err = iptablesClient.InsertUnique(defaultIpTable, aclInputRulesChain,
			cnt, ruleSpec...)
		if err != nil {
			logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
		} else {
			ingressGwRoutes = append(ingressGwRoutes, ruleInfo{
				table: defaultIpTable,
				chain: aclInputRulesChain,
				rule:  ruleSpec,
			})
		}

	}
	for _, rule := range ingressInfo.Rules {
		if !rule.Allow {
			continue
		}
		iptablesClient := i.ipv4Client
		if rule.SrcIP.IP.To4() == nil {
			iptablesClient = i.ipv6Client
		}
		rulesSpec := [][]string{}
		if len(rule.AllowedPorts) > 0 {

			for _, port := range rule.AllowedPorts {
				if port == "" {
					continue
				}
				ruleSpec := []string{"-s", rule.SrcIP.String()}
				if rule.DstIP.IP != nil {
					ruleSpec = append(ruleSpec, "-d", rule.DstIP.String())
				}
				if rule.AllowedProtocol.String() != "" && rule.AllowedProtocol != models.ALL {
					ruleSpec = append(ruleSpec, "-p", rule.AllowedProtocol.String())
				}
				if strings.Contains(port, "-") {
					port = strings.ReplaceAll(port, "-", ":")
				}
				ruleSpec = append(ruleSpec, "--dport", port)
				ruleSpec = append(ruleSpec, "-j", "ACCEPT")
				ruleSpec = appendNetmakerCommentToRule(ruleSpec)
				rulesSpec = append(rulesSpec, ruleSpec)
			}

		} else {
			ruleSpec := []string{"-s", rule.SrcIP.String()}
			if rule.DstIP.IP != nil {
				ruleSpec = append(ruleSpec, "-d", rule.DstIP.String())
			}
			if rule.AllowedProtocol.String() != "" && rule.AllowedProtocol != models.ALL {
				ruleSpec = append(ruleSpec, "-p", rule.AllowedProtocol.String())
			}
			ruleSpec = append(ruleSpec, "-j", "ACCEPT")
			ruleSpec = appendNetmakerCommentToRule(ruleSpec)
			rulesSpec = append(rulesSpec, ruleSpec)
		}
		for _, ruleSpec := range rulesSpec {
			// to avoid duplicate iface route rule,delete if exists
			iptablesClient.DeleteIfExists(defaultIpTable, aclInputRulesChain, ruleSpec...)
			err := iptablesClient.Insert(defaultIpTable, aclInputRulesChain, 1, ruleSpec...)
			if err != nil {
				logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
			} else {
				ingressGwRoutes = append(ingressGwRoutes, ruleInfo{
					table: defaultIpTable,
					chain: aclInputRulesChain,
					rule:  ruleSpec,
				})
			}
		}

	}

	ingressRules.rulesMap[staticNodeRules] = ingressGwRoutes
	ingressRules.extraInfo = ingressInfo
	ruleTable[ingressInfo.IngressID] = ingressRules
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

func (i *iptablesManager) getLastRuleCnt(table, chain string, v4 bool) int {
	// Get current rules
	var rules []string
	var err error
	if v4 {
		rules, err = i.ipv4Client.List(table, chain)
		if err != nil {
			log.Fatalf("Failed to list iptables rules: %v", err)
		}
	} else {
		rules, err = i.ipv6Client.List(table, chain)
		if err != nil {
			log.Fatalf("Failed to list iptables rules: %v", err)
		}
	}

	// Determine last but one position
	lastRuleNum := len(rules) - 1 // Subtract 1 because first line is the header
	if lastRuleNum < 2 {
		return 1
	}
	return lastRuleNum
}

func (i *iptablesManager) AddAclRules(server string, aclRules map[string]models.AclRule) {
	ruleTable := i.FetchRuleTable(server, aclTable)
	defer i.SaveRules(server, aclTable, ruleTable)
	i.mux.Lock()
	defer i.mux.Unlock()
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
			allowedIps := []string{}
			for _, ip := range aclRule.IPList {
				allowedIps = append(allowedIps, ip.String())
			}
			rulesSpec := [][]string{}
			if len(aclRule.AllowedPorts) > 0 {

				for _, port := range aclRule.AllowedPorts {
					if port == "" {
						continue
					}
					ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
					if aclRule.AllowedProtocol.String() != "" && aclRule.AllowedProtocol != models.ALL {
						ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
					}
					if strings.Contains(port, "-") {
						port = strings.ReplaceAll(port, "-", ":")
					}
					ruleSpec = append(ruleSpec, "--dport", port)
					//ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
					ruleSpec = append(ruleSpec, "-j", "ACCEPT")
					ruleSpec = appendNetmakerCommentToRule(ruleSpec)
					rulesSpec = append(rulesSpec, ruleSpec)
				}

			} else {
				ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
				if aclRule.AllowedProtocol.String() != "" && aclRule.AllowedProtocol != models.ALL {
					ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
				}
				//ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
				ruleSpec = append(ruleSpec, "-j", "ACCEPT")
				ruleSpec = appendNetmakerCommentToRule(ruleSpec)
				rulesSpec = append(rulesSpec, ruleSpec)
			}

			for _, ruleSpec := range rulesSpec {
				err := i.ipv4Client.Insert(defaultIpTable, aclInputRulesChain, 1, ruleSpec...)
				if err != nil {
					logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
				} else {
					rules = append(rules, ruleInfo{
						isIpv4: true,
						table:  defaultIpTable,
						chain:  aclInputRulesChain,
						rule:   ruleSpec,
					})

				}
			}
		}

		if len(aclRule.IP6List) > 0 {
			allowedIps := []string{}
			for _, ip := range aclRule.IP6List {
				allowedIps = append(allowedIps, ip.String())
			}
			rulesSpec := [][]string{}
			if len(aclRule.AllowedPorts) > 0 {

				for _, port := range aclRule.AllowedPorts {
					if port == "" {
						continue
					}
					ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
					if aclRule.AllowedProtocol.String() != "" && aclRule.AllowedProtocol != models.ALL {
						ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
					}
					if strings.Contains(port, "-") {
						port = strings.ReplaceAll(port, "-", ":")
					}
					ruleSpec = append(ruleSpec, "--dport", port)
					//ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
					ruleSpec = append(ruleSpec, "-j", "ACCEPT")
					ruleSpec = appendNetmakerCommentToRule(ruleSpec)
					rulesSpec = append(rulesSpec, ruleSpec)
				}

			} else {
				ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
				if aclRule.AllowedProtocol.String() != "" && aclRule.AllowedProtocol != models.ALL {
					ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
				}
				//ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
				ruleSpec = append(ruleSpec, "-j", "ACCEPT")
				ruleSpec = appendNetmakerCommentToRule(ruleSpec)
				rulesSpec = append(rulesSpec, ruleSpec)
			}

			for _, ruleSpec := range rulesSpec {
				err := i.ipv6Client.Insert(defaultIpTable, aclInputRulesChain, 1, ruleSpec...)
				if err != nil {
					logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
				} else {
					rules = append(rules, ruleInfo{
						isIpv4: false,
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

func (i *iptablesManager) UpsertAclRule(server string, aclRule models.AclRule) {
	ruleTable := i.FetchRuleTable(server, aclTable)
	defer i.SaveRules(server, aclTable, ruleTable)
	i.mux.Lock()
	defer i.mux.Unlock()
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
		allowedIps := []string{}
		for _, ip := range aclRule.IPList {
			allowedIps = append(allowedIps, ip.String())
		}
		rulesSpec := [][]string{}
		if len(aclRule.AllowedPorts) > 0 {
			for _, port := range aclRule.AllowedPorts {
				if port == "" {
					continue
				}
				ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
				if aclRule.AllowedProtocol.String() != "" {
					ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
				}
				if strings.Contains(port, "-") {
					port = strings.ReplaceAll(port, "-", ":")
				}
				ruleSpec = append(ruleSpec, "--dport", port)
				//ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
				ruleSpec = append(ruleSpec, "-j", "ACCEPT")
				ruleSpec = appendNetmakerCommentToRule(ruleSpec)
				rulesSpec = append(rulesSpec, ruleSpec)
			}

		} else {
			ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
			if aclRule.AllowedProtocol.String() != "" {
				ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
			}
			//ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
			ruleSpec = append(ruleSpec, "-j", "ACCEPT")
			ruleSpec = appendNetmakerCommentToRule(ruleSpec)
			rulesSpec = append(rulesSpec, ruleSpec)
		}
		for _, ruleSpec := range rulesSpec {
			err := i.ipv4Client.Insert(defaultIpTable, aclInputRulesChain, 1, ruleSpec...)
			if err != nil {
				logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
			} else {
				rules = append(rules, ruleInfo{
					isIpv4: true,
					table:  defaultIpTable,
					chain:  aclInputRulesChain,
					rule:   ruleSpec,
				})

			}
		}

	}
	if len(aclRule.IP6List) > 0 {
		allowedIps := []string{}
		for _, ip := range aclRule.IP6List {
			allowedIps = append(allowedIps, ip.String())
		}
		rulesSpec := [][]string{}
		if len(aclRule.AllowedPorts) > 0 {

			for _, port := range aclRule.AllowedPorts {
				if port == "" {
					continue
				}
				ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
				if aclRule.AllowedProtocol.String() != "" {
					ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
				}
				if strings.Contains(port, "-") {
					port = strings.ReplaceAll(port, "-", ":")
				}
				ruleSpec = append(ruleSpec, "--dport", port)
				//ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
				ruleSpec = append(ruleSpec, "-j", "ACCEPT")
				rulesSpec = append(rulesSpec, ruleSpec)
			}

		} else {
			ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
			if aclRule.AllowedProtocol.String() != "" {
				ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
			}
			//ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
			ruleSpec = append(ruleSpec, "-j", "ACCEPT")
			rulesSpec = append(rulesSpec, ruleSpec)
		}
		for _, ruleSpec := range rulesSpec {
			err := i.ipv6Client.Insert(defaultIpTable, aclInputRulesChain, 1, ruleSpec...)
			if err != nil {
				logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
			} else {
				rules = append(rules, ruleInfo{
					isIpv4: false,
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

func (i *iptablesManager) DeleteAclRule(server, aclID string) {
	ruleTable := i.FetchRuleTable(server, aclTable)
	defer i.SaveRules(server, aclTable, ruleTable)
	i.mux.Lock()
	defer i.mux.Unlock()
	rulesCfg, ok := ruleTable[aclID]
	if !ok {
		return
	}
	rules := rulesCfg.rulesMap[aclID]
	for _, rule := range rules {
		if rule.isIpv4 {
			i.ipv4Client.DeleteIfExists(rule.table, rule.chain, rule.rule...)
		} else {
			i.ipv6Client.DeleteIfExists(rule.table, rule.chain, rule.rule...)
		}
	}
	delete(ruleTable, aclID)

}

func (i *iptablesManager) AddAclEgressRules(server string, egressInfo models.EgressInfo) {
	ruleTable := i.FetchRuleTable(server, egressTable)
	defer i.SaveRules(server, egressTable, ruleTable)
	i.mux.Lock()
	defer i.mux.Unlock()
	if ruleTable == nil {
		ruleTable = make(ruletable)
	}
	aclRules := egressInfo.EgressFwRules
	rCfg := rulesCfg{
		rulesMap: make(map[string][]ruleInfo),
	}
	for _, aclRule := range aclRules {
		rules := []ruleInfo{}
		if len(aclRule.IPList) > 0 {
			allowedIps := []string{}
			for _, ip := range aclRule.IPList {
				if ip.IP == nil {
					continue
				}
				allowedIps = append(allowedIps, ip.String())
			}
			allowedDstIps := []string{}
			for _, ip := range aclRule.Dst {
				if ip.IP == nil {
					continue
				}
				allowedDstIps = append(allowedDstIps, ip.String())
			}
			rulesSpec := [][]string{}
			if len(aclRule.AllowedPorts) > 0 {

				for _, port := range aclRule.AllowedPorts {
					if port == "" {
						continue
					}
					ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
					if aclRule.AllowedProtocol.String() != "" && aclRule.AllowedProtocol != models.ALL {
						ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
					}
					if strings.Contains(port, "-") {
						port = strings.ReplaceAll(port, "-", ":")
					}

					if len(allowedDstIps) > 0 {
						ruleSpec = append(ruleSpec, "-d", strings.Join(allowedDstIps, ","))
					}

					ruleSpec = append(ruleSpec, "--dport", port)
					//ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
					ruleSpec = append(ruleSpec, "-j", "ACCEPT")
					ruleSpec = appendNetmakerCommentToRule(ruleSpec)
					rulesSpec = append(rulesSpec, ruleSpec)
				}

			} else {
				ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
				if aclRule.AllowedProtocol.String() != "" && aclRule.AllowedProtocol != models.ALL {
					ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
				}
				if len(allowedDstIps) > 0 {
					ruleSpec = append(ruleSpec, "-d", strings.Join(allowedDstIps, ","))
				}
				//ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
				ruleSpec = append(ruleSpec, "-j", "ACCEPT")
				ruleSpec = appendNetmakerCommentToRule(ruleSpec)
				rulesSpec = append(rulesSpec, ruleSpec)
			}

			for _, ruleSpec := range rulesSpec {
				err := i.ipv4Client.Insert(defaultIpTable, aclFwdRulesChain, 1, ruleSpec...)
				if err != nil {
					logger.Log(0, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
				} else {
					rules = append(rules, ruleInfo{
						isIpv4: true,
						table:  defaultIpTable,
						chain:  aclFwdRulesChain,
						rule:   ruleSpec,
					})

				}
			}
		}

		if len(aclRule.IP6List) > 0 {
			allowedIps := []string{}
			for _, ip := range aclRule.IP6List {
				if ip.IP == nil {
					continue
				}
				allowedIps = append(allowedIps, ip.String())
			}
			allowedDstIps := []string{}
			for _, ip := range aclRule.Dst6 {
				if ip.IP == nil {
					continue
				}
				allowedDstIps = append(allowedDstIps, ip.String())
			}
			rulesSpec := [][]string{}
			if len(aclRule.AllowedPorts) > 0 {

				for _, port := range aclRule.AllowedPorts {
					if port == "" {
						continue
					}
					ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
					if aclRule.AllowedProtocol.String() != "" && aclRule.AllowedProtocol != models.ALL {
						ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
					}
					if strings.Contains(port, "-") {
						port = strings.ReplaceAll(port, "-", ":")
					}
					if len(allowedDstIps) > 0 {
						ruleSpec = append(ruleSpec, "-d", strings.Join(allowedDstIps, ","))
					}
					ruleSpec = append(ruleSpec, "--dport", port)
					//ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
					ruleSpec = append(ruleSpec, "-j", "ACCEPT")
					ruleSpec = appendNetmakerCommentToRule(ruleSpec)
					rulesSpec = append(rulesSpec, ruleSpec)
				}

			} else {
				ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
				if aclRule.AllowedProtocol.String() != "" && aclRule.AllowedProtocol != models.ALL {
					ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
				}
				if len(allowedDstIps) > 0 {
					ruleSpec = append(ruleSpec, "-d", strings.Join(allowedDstIps, ","))
				}
				//ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
				ruleSpec = append(ruleSpec, "-j", "ACCEPT")
				ruleSpec = appendNetmakerCommentToRule(ruleSpec)
				rulesSpec = append(rulesSpec, ruleSpec)
			}

			for _, ruleSpec := range rulesSpec {
				err := i.ipv6Client.Insert(defaultIpTable, aclFwdRulesChain, 1, ruleSpec...)
				if err != nil {
					logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
				} else {
					rules = append(rules, ruleInfo{
						isIpv4: false,
						table:  defaultIpTable,
						chain:  aclFwdRulesChain,
						rule:   ruleSpec,
					})

				}
			}
		}
		if len(rules) > 0 {
			rCfg.rulesMap[aclRule.ID] = rules

		} else {
			delete(aclRules, aclRule.ID)
		}
	}
	rCfg.extraInfo = aclRules
	ruleTable[fmt.Sprintf("acl#%s", egressInfo.EgressID)] = rCfg
}

func (i *iptablesManager) UpsertAclEgressRule(server, egressID string, aclRule models.AclRule) {
	ruleTable := i.FetchRuleTable(server, egressTable)
	defer i.SaveRules(server, egressTable, ruleTable)
	i.mux.Lock()
	defer i.mux.Unlock()
	rCfg := ruleTable[egressID]
	extraInfo := rCfg.extraInfo.(map[string]models.AclRule)
	rules := []ruleInfo{}
	if len(aclRule.IPList) > 0 {
		allowedIps := []string{}
		for _, ip := range aclRule.IPList {
			if ip.IP == nil {
				continue
			}
			allowedIps = append(allowedIps, ip.String())
		}
		allowedDstIps := []string{}
		for _, ip := range aclRule.Dst {
			if ip.IP == nil {
				continue
			}
			allowedDstIps = append(allowedDstIps, ip.String())
		}
		rulesSpec := [][]string{}
		if len(aclRule.AllowedPorts) > 0 {
			for _, port := range aclRule.AllowedPorts {
				if port == "" {
					continue
				}
				ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
				if aclRule.AllowedProtocol.String() != "" {
					ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
				}
				if strings.Contains(port, "-") {
					port = strings.ReplaceAll(port, "-", ":")
				}
				if len(allowedDstIps) > 0 {
					ruleSpec = append(ruleSpec, "-d", strings.Join(allowedDstIps, ","))
				}
				ruleSpec = append(ruleSpec, "--dport", port)
				//ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
				ruleSpec = append(ruleSpec, "-j", "ACCEPT")
				ruleSpec = appendNetmakerCommentToRule(ruleSpec)
				rulesSpec = append(rulesSpec, ruleSpec)
			}

		} else {
			ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
			if aclRule.AllowedProtocol.String() != "" {
				ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
			}
			if len(allowedDstIps) > 0 {
				ruleSpec = append(ruleSpec, "-d", strings.Join(allowedDstIps, ","))
			}
			//ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
			ruleSpec = append(ruleSpec, "-j", "ACCEPT")
			ruleSpec = appendNetmakerCommentToRule(ruleSpec)
			rulesSpec = append(rulesSpec, ruleSpec)
		}
		for _, ruleSpec := range rulesSpec {
			err := i.ipv4Client.Insert(defaultIpTable, aclFwdRulesChain, 1, ruleSpec...)
			if err != nil {
				logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
			} else {
				rules = append(rules, ruleInfo{
					isIpv4: true,
					table:  defaultIpTable,
					chain:  aclFwdRulesChain,
					rule:   ruleSpec,
				})

			}
		}

	}
	if len(aclRule.IP6List) > 0 {
		allowedIps := []string{}
		for _, ip := range aclRule.IP6List {
			allowedIps = append(allowedIps, ip.String())
		}
		allowedDstIps := []string{}
		for _, ip := range aclRule.Dst6 {
			if ip.IP == nil {
				continue
			}
			allowedDstIps = append(allowedDstIps, ip.String())
		}
		rulesSpec := [][]string{}
		if len(aclRule.AllowedPorts) > 0 {

			for _, port := range aclRule.AllowedPorts {
				if port == "" {
					continue
				}
				ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
				if aclRule.AllowedProtocol.String() != "" {
					ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
				}
				if len(allowedDstIps) > 0 {
					ruleSpec = append(ruleSpec, "-d", strings.Join(allowedDstIps, ","))
				}
				if strings.Contains(port, "-") {
					port = strings.ReplaceAll(port, "-", ":")
				}
				ruleSpec = append(ruleSpec, "--dport", port)
				//ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
				ruleSpec = append(ruleSpec, "-j", "ACCEPT")
				rulesSpec = append(rulesSpec, ruleSpec)
			}

		} else {
			ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
			if aclRule.AllowedProtocol.String() != "" {
				ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
			}
			if len(allowedDstIps) > 0 {
				ruleSpec = append(ruleSpec, "-d", strings.Join(allowedDstIps, ","))
			}
			//ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
			ruleSpec = append(ruleSpec, "-j", "ACCEPT")
			rulesSpec = append(rulesSpec, ruleSpec)
		}
		for _, ruleSpec := range rulesSpec {
			err := i.ipv6Client.Insert(defaultIpTable, aclFwdRulesChain, 1, ruleSpec...)
			if err != nil {
				logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
			} else {
				rules = append(rules, ruleInfo{
					isIpv4: false,
					table:  defaultIpTable,
					chain:  aclFwdRulesChain,
					rule:   ruleSpec,
				})
			}
		}
	}
	if len(rules) > 0 {
		rCfg.rulesMap[aclRule.ID] = rules
		extraInfo[aclRule.ID] = aclRule
		rCfg.extraInfo = extraInfo
		ruleTable[egressID] = rCfg
	}
}

func (i *iptablesManager) DeleteAllAclEgressRules(server, egressID string) {
	ruleTable := i.FetchRuleTable(server, egressTable)
	defer i.SaveRules(server, egressTable, ruleTable)
	i.mux.Lock()
	defer i.mux.Unlock()
	rulesCfg, ok := ruleTable[egressID]
	if !ok {
		return
	}
	for _, rules := range rulesCfg.rulesMap {
		for _, rule := range rules {
			if rule.isIpv4 {
				i.ipv4Client.DeleteIfExists(rule.table, rule.chain, rule.rule...)
			} else {
				i.ipv6Client.DeleteIfExists(rule.table, rule.chain, rule.rule...)
			}
		}
	}
	delete(ruleTable, egressID)
}

func (i *iptablesManager) DeleteAclEgressRule(server, egressID, aclID string) {
	ruleTable := i.FetchRuleTable(server, egressTable)
	defer i.SaveRules(server, egressTable, ruleTable)
	i.mux.Lock()
	defer i.mux.Unlock()
	rulesCfg, ok := ruleTable[egressID]
	if !ok {
		return
	}
	rules := rulesCfg.rulesMap[aclID]
	for _, rule := range rules {
		if rule.isIpv4 {
			i.ipv4Client.DeleteIfExists(rule.table, rule.chain, rule.rule...)
		} else {
			i.ipv6Client.DeleteIfExists(rule.table, rule.chain, rule.rule...)
		}
	}
	delete(rulesCfg.rulesMap, aclID)
	ruleTable[egressID] = rulesCfg
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

func (i *iptablesManager) clearNetmakerRules(table, chain string) {
	// List all rules in the specified chain
	rules, err := i.ipv4Client.List(table, chain)
	if err != nil {
		logger.Log(1, "Failed to list rules: ", table, chain, err.Error())
	}
	// Iterate through rules to find the one with the target comment
	for _, rule := range rules {
		if containsComment(rule, netmakerSignature) {
			// Delete the rule once found
			// Split the rule into components
			ruleComponents := strings.Fields(rule)
			if len(ruleComponents) > 2 {
				ruleComponents = ruleComponents[2:]
			}
			err = i.ipv4Client.Delete(table, chain, ruleComponents...)
			if err != nil {
				logger.Log(4, "Failed to delete rule: ", rule, err.Error())
			}
		}
	}
	rules, err = i.ipv6Client.List(table, chain)
	if err != nil {
		logger.Log(1, "Failed to list v6 rules: ", table, chain, err.Error())
	}

	// Iterate through rules to find the one with the target comment
	for _, rule := range rules {
		if containsComment(rule, netmakerSignature) {
			// Delete the rule once found
			// Split the rule into components
			ruleComponents := strings.Fields(rule)
			if len(ruleComponents) > 2 {
				ruleComponents = ruleComponents[2:]
			}
			err = i.ipv4Client.Delete(table, chain, ruleComponents...)
			if err != nil {
				logger.Log(4, "Failed to delete rule: ", rule, err.Error())
			}

		}
	}
}

// Helper function to check if a rule contains a specific comment
func containsComment(rule string, comment string) bool {
	return strings.Contains(rule, fmt.Sprintf("--comment %s", comment))
}

// iptablesManager.FetchRuleTable - fetches the rule table by table name
func (i *iptablesManager) FetchRuleTable(server string, tableName string) ruletable {
	i.mux.Lock()
	defer i.mux.Unlock()
	var rules ruletable
	switch tableName {
	case ingressTable:
		rules = i.ingRules[server]
	case egressTable:
		rules = i.engressRules[server]
	case aclTable:
		rules = i.aclRules[server]
	}
	if rules == nil {
		rules = make(ruletable)
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
	case aclTable:
		i.aclRules[server] = rules
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

	for _, rules := range rulesTable[peerKey].rulesMap {
		for _, rule := range rules {
			err := i.ipv4Client.DeleteIfExists(rule.table, rule.chain, rule.rule...)
			if err != nil {
				slog.Debug("failed to del egress rule: ", "error", fmt.Errorf("iptables: error while removing existing %s rules [%v] for %s: %v",
					rule.table, rule.rule, peerKey, err))
			}
			err = i.ipv6Client.DeleteIfExists(rule.table, rule.chain, rule.rule...)
			if err != nil {
				slog.Debug("failed to del egress rule: ", "error", fmt.Errorf("iptables: error while removing existing %s rules [%v] for %s: %v",
					rule.table, rule.rule, peerKey, err))
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
	logger.Log(0, "flushing netmaker rules...")
	i.removeJumpRules()
	i.clearNetmakerRules(defaultIpTable, iptableINChain)
	i.clearNetmakerRules(defaultIpTable, iptableFWDChain)
	i.cleanup(defaultIpTable, aclInputRulesChain)
	i.cleanup(defaultIpTable, aclFwdRulesChain)
	i.cleanup(defaultIpTable, aclOutputRulesChain)
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
