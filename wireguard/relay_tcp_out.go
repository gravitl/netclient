package wireguard

import (
	"errors"
	"sync"
)

// tcpOutQueueSize bounds async uplink sends so Bind.Send never blocks on TLS I/O
// while WireGuard holds device.net.RLock (which would freeze Close / wg show).
const tcpOutQueueSize = 256

var (
	errTCPOutQueueFull = errors.New("tcp uplink: outbound queue full")

	tcpOutOnce sync.Once
	tcpOutCh   chan func()
)

func ensureTCPOutWorker() {
	tcpOutOnce.Do(func() {
		tcpOutCh = make(chan func(), tcpOutQueueSize)
		go func() {
			for fn := range tcpOutCh {
				fn()
			}
		}()
	})
}

// enqueueTCPOut runs fn asynchronously. Bind.Send must use this for TCP paths.
func enqueueTCPOut(fn func()) error {
	ensureTCPOutWorker()
	select {
	case tcpOutCh <- fn:
		return nil
	default:
		return errTCPOutQueueFull
	}
}
