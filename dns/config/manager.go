package config

import (
	"net"
)

type Config struct {
	Nameservers     []net.IP
	MatchDomains    []string
	SearchDomains   []string
	SplitDNS        bool
	Remove          bool
	ADCompatEnabled bool     // skip LAN DNS override; use NRPT only for overlay domains
	IsDC            bool     // domain controller — skip all DNS modifications
	ADDomainSuffs   []string // AD domain suffixes to exclude from NRPT namespaces
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
