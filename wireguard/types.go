package wireguard

// NCIface - represents a Netclient network interface
type NCIface struct {
	Iface netIface
	Name  string
	MTU   int
}

// NewNCIFace - creates a new Netclient interface in memory
func NewNCIface(mtu int) *NCIface {
	return &NCIface{
		Name: getName(),
		MTU:  mtu,
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
