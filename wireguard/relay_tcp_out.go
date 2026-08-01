package wireguard

import (
	"errors"
	"sync"
	"time"

	"golang.org/x/exp/slog"
)

// tcpOutQueueSize bounds async uplink sends so Bind.Send never blocks on TLS I/O
// while WireGuard holds device.net.RLock (which would freeze Close / wg show).
const tcpOutQueueSize = 256

var (
	errTCPOutQueueFull = errors.New("tcp uplink: outbound queue full")

	tcpOutMu   sync.Mutex
	tcpOutCh   chan func()
	tcpOutWG   sync.WaitGroup
)

func ensureTCPOutWorkerLocked() {
	if tcpOutCh != nil {
		return
	}
	ch := make(chan func(), tcpOutQueueSize)
	tcpOutCh = ch
	tcpOutWG.Add(1)
	go func(c chan func()) {
		defer tcpOutWG.Done()
		for fn := range c {
			fn()
		}
	}(ch)
}

func ensureTCPOutWorker() {
	tcpOutMu.Lock()
	defer tcpOutMu.Unlock()
	ensureTCPOutWorkerLocked()
}

// enqueueTCPOut runs fn asynchronously. Bind.Send must use this for TCP paths.
func enqueueTCPOut(fn func()) error {
	tcpOutMu.Lock()
	ensureTCPOutWorkerLocked()
	ch := tcpOutCh
	tcpOutMu.Unlock()
	if ch == nil {
		return errTCPOutQueueFull
	}
	select {
	case ch <- fn:
		return nil
	default:
		return errTCPOutQueueFull
	}
}

// DrainTCPOutQueue closes the current outbound worker, waits up to timeout for
// in-flight jobs, then allows a fresh worker on the next enqueue.
func DrainTCPOutQueue(timeout time.Duration) {
	tcpOutMu.Lock()
	ch := tcpOutCh
	tcpOutCh = nil
	tcpOutMu.Unlock()
	if ch == nil {
		return
	}
	close(ch)
	done := make(chan struct{})
	go func() {
		tcpOutWG.Wait()
		close(done)
	}()
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	select {
	case <-done:
	case <-time.After(timeout):
		slog.Warn("tcp uplink: outbound queue drain timed out", "timeout", timeout)
	}
}

// PrepareUserspaceTeardown clears TCP uplink wiring and drains async sends.
// Call before Device.Close / iface recreate so Bind.Send and recv paths cannot hang Close.
func PrepareUserspaceTeardown() {
	ClearClientRelay()
	ClearAllTCPPeerRoutes()
	SetRelayTCPUplink(nil)
	SetTCPUplinkServer(nil)
	DrainTCPOutQueue(2 * time.Second)
}
