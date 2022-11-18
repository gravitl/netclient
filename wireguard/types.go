package wireguard

import (
	"github.com/gravitl/netclient/config"
)

// NCIface - represents a Netclient network interface
type NCIface struct {
	Iface    netIface
	Settings *config.Node
}

// NewNCIFace - creates a new Netclient interface in memory
func NewNCIface(n *config.Node) *NCIface {
	return &NCIface{
		Settings: n,
	}
}

func (n *NCIface) Close() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()

	return n.Close()
}

// == private ==
type netIface interface {
	Close() error
}
