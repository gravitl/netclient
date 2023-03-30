package networking

import (
	"time"
)

// reqTimeout - five seconds for client request to happen
const (
	reqTimeout               = time.Second * 1
	latencyVarianceThreshold = 3
)

// messages to hande client/server comms
var messages = struct {
	Wrong   string
	Success string
}{
	Wrong:   "WRONG",
	Success: "PONG",
}

// the type to send between client + server for local address detection
type bestIfaceMsg struct {
	Hash      string `json:"hash"`
	TimeStamp int64  `json:"time_stamp"`
}
