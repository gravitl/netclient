package networking

import (
	"net/netip"
	"time"
)

// reqTimeout - five seconds for client request to happen
const (
	reqTimeout = time.Second * 5
)

// messages to hande client/server comms
var messages = struct {
	Wrong     string
	Delimiter string
	Success   string
}{
	Wrong:     "WRONG",
	Delimiter: "(#)",
	Success:   "PONG",
}

// ifaceCacheValue - type for storage for best local address
type ifaceCacheValue struct {
	Latency  time.Duration
	Endpoint netip.Addr
}
