package config

import "net"

type Config struct {
	Interface     string
	Nameservers   []net.IP
	SearchDomains []string
}

type Manager interface {
	Configure(config Config) error
	SupportsInterfaceSpecificConfig() bool
}
