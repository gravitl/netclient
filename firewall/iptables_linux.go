package firewall

import (
	"errors"
	"fmt"
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
	ipv6           = "ipv6"
	ipv4           = "ipv4"
	defaultIpTable = "filter"
	//netmakerFilterChain = "netmakerfilter"
	defaultNatTable     = "nat"
	netmakerNatChain    = "netmakernat"
	iptableFWDChain     = "FORWARD"
	iptableINChain      = "INPUT"
	nattablePRTChain    = "POSTROUTING"
	netmakerSignature   = "NETMAKER"
	aclInputRulesChain  = "NETMAKER-ACL-IN"
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
	dropRules = []ruleInfo{

		aclInChainDropRule,
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
			rule: []string{"-i", ncutils.GetInterfaceName(), "-j", aclInputRulesChain,
				"-m", "comment", "--comment", netmakerSignature},
			table: defaultIpTable,
			chain: iptableFWDChain,
		},
		{
			rule: []string{"-o", ncutils.GetInterfaceName(), "-j", aclOutputRulesChain,
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

func (i *iptablesManager) ChangeACLTarget(target string) {
	fmt.Println("===> ACL TARGET ", target)
	ruleSpec := aclInChainDropRule.rule
	table := aclInChainDropRule.table
	chain := aclInChainDropRule.chain
	ruleSpec[len(ruleSpec)-1] = target
	ok4, _ := i.ipv4Client.Exists(table, chain, ruleSpec...)
	ok6, _ := i.ipv4Client.Exists(table, chain, ruleSpec...)
	if ok4 && ok6 {
		return
	}
	fmt.Println("===>CHANGING ACL TARGET ", target)
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

	iptablesClient := i.ipv4Client
	// Set the policy To accept on forward chain
	iptablesClient.ChangePolicy(defaultIpTable, iptableFWDChain, "ACCEPT")

	ruleSpec := []string{"-i", "netmaker", "-j", aclInputRulesChain}
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
	ruleSpec = []string{"-o", "netmaker", "-j", aclOutputRulesChain}
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
	// remove jump rules
	i.removeJumpRules()
	i.cleanup(defaultNatTable, netmakerNatChain)
	i.clearNetmakerRules(defaultIpTable, iptableINChain)
	i.clearNetmakerRules(defaultIpTable, iptableFWDChain)
	//errMSGFormat := "iptables: failed creating %s chain %s,error: %v"

	err := createChain(i.ipv4Client, defaultNatTable, netmakerNatChain)
	if err != nil {
		logger.Log(1, "failed to create netmaker chain: ", err.Error())
		return err
	}
	err = createChain(i.ipv4Client, defaultIpTable, aclInputRulesChain)
	if err != nil {
		logger.Log(1, "failed to create netmaker chain: ", err.Error())
		return err
	}
	err = createChain(i.ipv4Client, defaultIpTable, aclOutputRulesChain)
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

	i.AddDropRules(dropRules)

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
	ruleTable[egressInfo.EgressID] = rulesCfg{
		rulesMap: make(map[string][]ruleInfo),
	}
	egressGwRoutes := []ruleInfo{}
	for _, egressGwRange := range egressInfo.EgressGWCfg.Ranges {
		if egressInfo.EgressGWCfg.NatEnabled == "yes" {
			iptablesClient := i.ipv4Client
			source := egressInfo.Network.String()
			if !isAddrIpv4(egressGwRange) {
				iptablesClient = i.ipv6Client
				source = egressInfo.Network6.String()
			}
			egressRangeIface, err := getInterfaceName(config.ToIPNet(egressGwRange))
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
					ruleSpec = append(ruleSpec, "--dport", port)
					ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
					ruleSpec = append(ruleSpec, "-j", "ACCEPT")
					ruleSpec = appendNetmakerCommentToRule(ruleSpec)
					rulesSpec = append(rulesSpec, ruleSpec)
				}

			} else {
				ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
				if aclRule.AllowedProtocol.String() != "" && aclRule.AllowedProtocol != models.ALL {
					ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
				}
				ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
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
					ruleSpec = append(ruleSpec, "--dport", port)
					ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
					ruleSpec = append(ruleSpec, "-j", "ACCEPT")
					ruleSpec = appendNetmakerCommentToRule(ruleSpec)
					rulesSpec = append(rulesSpec, ruleSpec)
				}

			} else {
				ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
				if aclRule.AllowedProtocol.String() != "" && aclRule.AllowedProtocol != models.ALL {
					ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
				}
				ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
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
						isIpv4: true,
						table:  defaultIpTable,
						chain:  aclInputRulesChain,
						rule:   ruleSpec,
					})

				}
			}
		}
		if len(rules) > 0 {
			fmt.Printf("====> IN ADDACLRULES: %+v\n", rules)
			rCfg := rulesCfg{
				rulesMap: map[string][]ruleInfo{
					aclRule.ID: rules,
				},
				extraInfo: aclRule,
			}
			ruleTable[aclRule.ID] = rCfg
		}
	}
	fmt.Printf("===> AFTER ADDACLRULES: %+v\n", ruleTable)
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
				ruleSpec = append(ruleSpec, "--dport", port)
				ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
				ruleSpec = append(ruleSpec, "-j", "ACCEPT")
				ruleSpec = appendNetmakerCommentToRule(ruleSpec)
				rulesSpec = append(rulesSpec, ruleSpec)
			}

		} else {
			ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
			if aclRule.AllowedProtocol.String() != "" {
				ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
			}
			ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
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
				ruleSpec = append(ruleSpec, "--dport", port)
				ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
				ruleSpec = append(ruleSpec, "-j", "ACCEPT")
				rulesSpec = append(rulesSpec, ruleSpec)
			}

		} else {
			ruleSpec := []string{"-s", strings.Join(allowedIps, ",")}
			if aclRule.AllowedProtocol.String() != "" {
				ruleSpec = append(ruleSpec, "-p", aclRule.AllowedProtocol.String())
			}
			ruleSpec = append(ruleSpec, "-m", "addrtype", "--dst-type", "LOCAL")
			ruleSpec = append(ruleSpec, "-j", "ACCEPT")
			rulesSpec = append(rulesSpec, ruleSpec)
		}
		for _, ruleSpec := range rulesSpec {
			err := i.ipv6Client.Insert(defaultIpTable, aclInputRulesChain, 1, ruleSpec...)
			if err != nil {
				logger.Log(1, fmt.Sprintf("failed to add rule: %v, Err: %v ", ruleSpec, err.Error()))
			} else {
				rules = append(rules, ruleInfo{
					table: defaultIpTable,
					chain: aclInputRulesChain,
					rule:  ruleSpec,
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
	i.cleanup(defaultIpTable, aclOutputRulesChain)
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
