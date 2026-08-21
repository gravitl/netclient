package wireguard

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/exp/slog"
)

const (
	// tcpOutQueueSize bounds async uplink sends so Bind.Send never blocks on TLS I/O
	// while WireGuard holds device.net.RLock (which would freeze Close / wg show).
	//
	// 1024 full-MTU packets is roughly 100ms of a 100Mbit link, enough to ride out
	// a congested TLS write but under the tunnelled TCP's retransmit timeout, so a
	// stall sheds packets instead of delivering ones the sender already gave up on.
	// It also matches wireguard-go's own QueueOutboundSize, the stage feeding this
	// one.
	tcpOutQueueSize = 1024
	// tcpInQueueSize bounds gateway→client ingress, the heavy direction for an
	// exit node.
	tcpInQueueSize = 1024
)

var (
	errTCPOutQueueFull = errors.New("tcp uplink: outbound queue full")

	tcpOutMu       sync.Mutex
	tcpOutCh       chan func()
	tcpOutWG       sync.WaitGroup
	tcpOutDraining atomic.Bool

	tcpOutDrops        tcpDropStats
	tcpInQueueDrops    tcpDropStats
	tcpInEndpointDrops tcpDropStats
	tcpInOversizeDrops tcpDropStats
)

// tcpDropStats counts dropped packets and logs at most once per interval.
// Logging every drop at exit-node packet rates would flood the log and hide the
// aggregate loss.
type tcpDropStats struct {
	count   atomic.Uint64
	lastLog atomic.Int64
}

const tcpDropLogInterval = 5 * time.Second

func (s *tcpDropStats) note(msg string) {
	total := s.count.Add(1)
	now := time.Now().UnixNano()
	last := s.lastLog.Load()
	if last != 0 && now-last < int64(tcpDropLogInterval) {
		return
	}
	if !s.lastLog.CompareAndSwap(last, now) {
		return
	}
	slog.Warn(msg, "dropped_total", total)
}

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

// enqueueTCPOut runs fn asynchronously. Bind.Send must use this for TCP paths.
func enqueueTCPOut(fn func()) error {
	tcpOutMu.Lock()
	defer tcpOutMu.Unlock()
	if tcpOutDraining.Load() {
		return errTCPOutQueueFull
	}
	ensureTCPOutWorkerLocked()
	ch := tcpOutCh
	if ch == nil {
		return errTCPOutQueueFull
	}
	// Send under tcpOutMu so DrainTCPOutQueue cannot close ch concurrently.
	select {
	case ch <- fn:
		return nil
	default:
		tcpOutDrops.note("tcp uplink: outbound queue full, dropping packet")
		return errTCPOutQueueFull
	}
}

// DrainTCPOutQueue closes the current outbound worker, waits up to timeout for
// in-flight jobs, then allows a fresh worker on the next enqueue.
func DrainTCPOutQueue(timeout time.Duration) {
	tcpOutMu.Lock()
	tcpOutDraining.Store(true)
	ch := tcpOutCh
	tcpOutCh = nil
	tcpOutMu.Unlock()
	if ch == nil {
		tcpOutDraining.Store(false)
		return
	}
	close(ch)
	done := make(chan struct{})
	go func() {
		tcpOutWG.Wait()
		tcpOutDraining.Store(false)
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
