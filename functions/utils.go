package functions

import (
	"os"
	"strings"

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

// IsContainerized returns true if the process appears to be running inside
// a Docker container, Kubernetes pod, or other containerd-based runtime.
func IsContainerized() bool {
	// Docker: /.dockerenv exists
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	// Kubernetes: service account token or env
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		return true
	}
	// Cgroups: look for docker, containerd, kubepods, crio
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(data)
		for _, pattern := range []string{"docker", "containerd", "kubepods", "crio"} {
			if strings.Contains(s, pattern) {
				return true
			}
		}
	}
	return false
}
