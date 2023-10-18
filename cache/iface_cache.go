package cache

import (
	"net/netip"
	"sync"
	"time"
)

// EndpointCache - keeps the best found endpoints between peers based on public key
var EndpointCache sync.Map

// EndpointCacheValue - type for storage for best local address
type EndpointCacheValue struct {
	Latency  time.Duration
	Endpoint netip.AddrPort
}

// ServerAddrCache - server addresses mapped to server names
var ServerAddrCache sync.Map // config.Server.Name -> []net.IP
