package cache

import (
	"net"
	"sync"
)

// EndpointCache - keeps the best found endpoints between peers based on public key
var EndpointCache sync.Map

// EndpointCacheValue - type for storage for best local address
type EndpointCacheValue struct {
	Endpoint *net.UDPAddr
}

// ServerAddrCache - server addresses mapped to server names
var ServerAddrCache sync.Map // config.Server.Name -> []net.IP
