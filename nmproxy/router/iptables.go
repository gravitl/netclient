package router

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func isIptablesSupported() bool {
	_, err4 := exec.LookPath("iptables")
	_, err6 := exec.LookPath("ip6tables")
	return err4 == nil && err6 == nil
}

// constants needed to manage and create iptable rules
const (
	ipv6                    = "ipv6"
	ipv4                    = "ipv4"
	defaultIpTable          = "filter"
	defaultNetmakerChain    = "netmakerfilter"
	defaultNatTable         = "nat"
	defaultNetmakerNatChain = "netmakernat"
	defaultIptableFWDChain  = "FORWARD"
)

type RuleInfo struct {
	ipVersion string
	rule      []string
	table     string
	chain     string
}

type iptablesManager struct {
	ctx        context.Context
	stop       context.CancelFunc
	ipv4Client *iptables.IPTables
	ipv6Client *iptables.IPTables
	ingRules   map[string]map[string][]RuleInfo
	mux        sync.Mutex
}

func createChain(iptables *iptables.IPTables, table, newChain string) error {

	err := iptables.NewChain(table, newChain)
	if err != nil {
		return fmt.Errorf("couldn't create %s chain %s in %s table, error: %v", iptablesProtoToString(iptables.Proto()), newChain, table, err)
	}
	return nil
}

// CleanRoutingRules cleans existing iptables resources that we created by the agent
func (i *iptablesManager) CleanRoutingRules() {
	i.mux.Lock()
	defer i.mux.Unlock()

	log.Debug("flushing tables")
	// errMSGFormat := "iptables: failed cleaning %s chain %s,error: %v"

	log.Info("done cleaning up iptables rules")
}

// CreateChains - creates default chains and rules
func (i *iptablesManager) CreateChains() error {
	i.mux.Lock()
	defer i.mux.Unlock()

	cleanup(i.ipv4Client, defaultIpTable, defaultNetmakerChain)
	cleanup(i.ipv4Client, defaultNatTable, defaultNetmakerNatChain)
	cleanup(i.ipv6Client, defaultIpTable, defaultNetmakerChain)
	cleanup(i.ipv6Client, defaultNatTable, defaultNetmakerNatChain)

	//errMSGFormat := "iptables: failed creating %s chain %s,error: %v"

	err := createChain(i.ipv4Client, defaultIpTable, defaultNetmakerChain)
	if err != nil {
		log.Fatal("failed to create netmaker chain: ", err)
	}
	err = createChain(i.ipv4Client, defaultNatTable, defaultNetmakerNatChain)
	if err != nil {
		log.Fatal("failed to create netmaker chain: ", err)
	}
	// set default rules
	insertDefaultRules(i.ipv4Client, defaultIpTable, defaultNetmakerChain)
	insertDefaultRules(i.ipv4Client, defaultNatTable, defaultNetmakerNatChain)

	err = createChain(i.ipv6Client, defaultIpTable, defaultNetmakerChain)
	if err != nil {
		log.Fatal("failed to create netmaker chain: ", err)
	}
	err = createChain(i.ipv6Client, defaultNatTable, defaultNetmakerNatChain)
	if err != nil {
		log.Fatal("failed to create netmaker chain: ", err)
	}
	// set default rules
	insertDefaultRules(i.ipv6Client, defaultIpTable, defaultNetmakerChain)
	insertDefaultRules(i.ipv6Client, defaultNatTable, defaultNetmakerNatChain)

	return nil
}

func insertDefaultRules(i *iptables.IPTables, table, chain string) {
	//iptables -A newchain -i netmaker -j DROP
	//iptables -A newchain -j RETURN
	if table == defaultIpTable {
		ruleSpec := []string{"-i", "netmaker", "-j", "DROP"}
		err := i.Append(table, chain, ruleSpec...)
		if err != nil {
			log.Println("failed to add rule: ", ruleSpec, err.Error())
		}
		ruleSpec = []string{"-j", "RETURN"}
		err = i.Append(table, chain, ruleSpec...)
		if err != nil {
			log.Println("failed to add rule: ", ruleSpec, err.Error())
		}
	} else {
		//	iptables -t nat -A POSTROUTING  -o netmaker -j netmakernat
		ruleSpec := []string{"-o", "netmaker", "-j", chain}
		err := i.Append(table, "POSTROUTING", ruleSpec...)
		if err != nil {
			log.Println("failed to add rule: ", ruleSpec, err.Error())
		}
		// iptables -t nat -A netmakernat -j RETURN
		ruleSpec = []string{"-j", "RETURN"}
		err = i.Append(table, chain, ruleSpec...)
		if err != nil {
			log.Println("failed to add rule: ", ruleSpec, err.Error())
		}
	}

}

// genRuleSpec generates rule specification with comment identifier
func genRuleSpec(jump, id, source, destination string) []string {
	return []string{"-s", source, "-d", destination, "-j", jump, "-m", "comment", "--comment", id}
}

// getRuleRouteID returns the rule ID if matches our prefix
func getRuleRouteID(rule []string) string {
	for i, flag := range rule {
		if flag == "--comment" {
			id := rule[i+1]
			if strings.HasPrefix(id, "netmaker-") {
				return id
			}
		}
	}
	return ""
}

// InsertIngressRoutingRules inserts an iptables rule pair to the forwarding chain and if enabled, to the nat chain
func (i *iptablesManager) InsertIngressRoutingRules(r ingressRoute) error {
	i.mux.Lock()
	defer i.mux.Unlock()
	prefix, err := netip.ParsePrefix(r.remoteClientAddr.String())
	if err != nil {
		return err
	}
	ipVersion := ipv4
	iptablesClient := i.ipv4Client
	if prefix.Addr().Unmap().Is6() {
		iptablesClient = i.ipv6Client
		ipVersion = ipv6
	}
	i.ingRules[r.remotePeerKey.String()] = make(map[string][]RuleInfo)
	//iptables -A FORWARD -s 10.24.52.252/32 ! -d 10.24.52.4/32 -p icmp -j newchain
	//iptables -A newchain -d 10.24.52.3/32 -p icmp -j ACCEPT
	ruleSpec := []string{"-s", r.remoteClientAddr.String(), "!", "-d", r.ingGWAddr.String(), "-j", defaultNetmakerChain}
	err = iptablesClient.Insert(defaultIpTable, defaultIptableFWDChain, 1, ruleSpec...)
	if err != nil {
		log.Println("failed to add rule: ", ruleSpec, err.Error())
	}
	i.ingRules[r.remotePeerKey.String()][r.remotePeerKey.String()] = []RuleInfo{

		{
			ipVersion: ipVersion,
			rule:      ruleSpec,
			chain:     defaultIptableFWDChain,
			table:     defaultIpTable,
		},
	}

	for _, peerInfo := range r.peers {
		ruleSpec := []string{"-d", peerInfo.peerAddr.String(), "-j", "ACCEPT"}
		err := iptablesClient.Insert(defaultIpTable, defaultNetmakerChain, 1, ruleSpec...)
		if err != nil {
			log.Println("failed to add rule: ", ruleSpec, err.Error())
		}
		i.ingRules[r.remotePeerKey.String()][peerInfo.peerKey.String()] = []RuleInfo{
			{
				ipVersion: ipVersion,
				rule:      ruleSpec,
				chain:     defaultNetmakerChain,
				table:     defaultIpTable,
			},
		}

	}
	if !r.masquerade {
		return nil
	}
	// iptables -t nat -A netmakernat  -s 10.24.52.252/32 -o netmaker -j MASQUERADE
	// iptables -t nat -A netmakernat -d 10.24.52.252/32 -o netmaker -j MASQUERADE
	ruleSpec = []string{"-s", r.remoteClientAddr.String(), "-o", "netmaker", "-j", "MASQUERADE"}
	err = iptablesClient.Append(defaultNatTable, defaultNetmakerNatChain, ruleSpec...)
	if err != nil {
		log.Println("failed to add rule: ", ruleSpec, err.Error())
	}
	routes := i.ingRules[r.remotePeerKey.String()][r.remotePeerKey.String()]
	routes = append(routes, RuleInfo{
		ipVersion: ipVersion,
		rule:      ruleSpec,
		table:     defaultNatTable,
		chain:     defaultNetmakerNatChain,
	})
	ruleSpec = []string{"-d", r.remoteClientAddr.String(), "-o", "netmaker", "-j", "MASQUERADE"}
	err = iptablesClient.Append(defaultNatTable, defaultNetmakerNatChain, ruleSpec...)
	if err != nil {
		log.Println("failed to add rule: ", ruleSpec, err.Error())
	}
	routes = append(routes, RuleInfo{
		ipVersion: ipVersion,
		rule:      ruleSpec,
		table:     defaultNatTable,
		chain:     defaultNetmakerNatChain,
	})
	i.ingRules[r.remotePeerKey.String()][r.remotePeerKey.String()] = routes

	return nil
}
func cleanup(i *iptables.IPTables, table, chain string) {

	i.ClearAndDeleteChain(table, chain)
	i.ClearAll()
}

// RemoveRoutingRules removes an iptables rule pair from forwarding and nat chains
func (i *iptablesManager) RemoveRoutingRules() error {
	i.mux.Lock()
	defer i.mux.Unlock()

	return nil
}

// removeRoutingRule removes an iptables rule
func (i *iptablesManager) removeIngRoutingRule(indexedPeerKey, peerKey wgtypes.Key) error {
	var err error
	var rulesInfo []RuleInfo
	var ok bool
	if rulesInfo, ok = i.ingRules[indexedPeerKey.String()][peerKey.String()]; !ok {
		return errors.New("no rules found")
	}
	for _, rInfo := range rulesInfo {
		iptablesClient := i.ipv4Client
		if rInfo.ipVersion == ipv6 {
			iptablesClient = i.ipv6Client
		}
		err = iptablesClient.DeleteIfExists(rInfo.table, rInfo.chain, rInfo.rule...)
		if err != nil {
			return fmt.Errorf("iptables: error while removing existing %v rule from %s: %v", rInfo.rule, rInfo.chain, err)
		}
	}

	delete(i.ingRules[indexedPeerKey.String()], peerKey.String())
	return nil
}

func iptablesProtoToString(proto iptables.Protocol) string {
	if proto == iptables.ProtocolIPv6 {
		return ipv6
	}
	return ipv4
}
