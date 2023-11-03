package networking

// messages to hande client/server comms
var messages = struct {
	Wrong   string
	Success string
}{
	Wrong:   "WRONG",
	Success: "PONG",
}
