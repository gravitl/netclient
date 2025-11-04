package config

import (
	"net"
)

type Config struct {
	Nameservers   []net.IP
	MatchDomains  []string
	SearchDomains []string
	SplitDNS      bool
	Remove        bool
}

type Manager interface {
	Configure(iface string, config Config) error
}

type ManagerOptions struct {
	cleanupResidual    bool
	residualInterfaces []string
}

type ManagerOption func(*ManagerOptions)

func CleanupResidualInterfaceConfigs(interfaces ...string) ManagerOption {
	return func(o *ManagerOptions) {
		o.cleanupResidual = true
		o.residualInterfaces = interfaces
	}
}
