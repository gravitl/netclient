package functions

import (
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logic"
	"github.com/gravitl/netmaker/models"
)

func FilterDnsNameservers(nameservers []models.Nameserver) []models.Nameserver {
	if len(nameservers) == 0 {
		return nil
	}

	filters := make(map[string]bool)
	for _, node := range config.GetNodes() {
		if node.Address.IP.String() != "<nil>" {
			filters[node.Address.IP.String()] = true
		}

		if node.Address6.IP.String() != "<nil>" {
			filters[node.Address6.IP.String()] = true
		}
	}

	var filteredNs []models.Nameserver
	for _, ns := range nameservers {
		ns.IPs = logic.FilterOutIPs(ns.IPs, filters)
		if len(ns.IPs) != 0 {
			filteredNs = append(filteredNs, ns)
		}
	}

	return filteredNs
}
