package wireguard

import (
	"github.com/gravitl/netclient/config"
)

// NCIface - represents a Netclient network interface
type NCIface struct {
	Iface netIface
	Host  *config.Config
	Node  *config.Node
}

// NewNCIFace - creates a new Netclient interface in memory
func NewNCIface(n *config.Node, h *config.Config) *NCIface {
	return &NCIface{
		Node: n,
		Host: h,
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
