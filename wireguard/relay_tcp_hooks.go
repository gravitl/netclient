package wireguard

import (
	"context"
	"os"
	"strings"
	"sync"

	"golang.org/x/exp/slog"
)

// envRelayTCPAddr matches internal/proxyuplink.EnvRelayTCPAddr (TCP relay uplink toggle).
const envRelayTCPAddr = "NC_RELAY_TCP_UPLINK_ADDR"

func relayTCPUplinkEnvConfigured() bool {
	return strings.TrimSpace(os.Getenv(envRelayTCPAddr)) != ""
}

// relayTCPUplink is implemented by proxyuplink.Manager (SendPacket).
type relayTCPUplink interface {
	SendPacket(ctx context.Context, pkt []byte) error
}

var (
	relayTCPMu sync.RWMutex
	relayTCP   relayTCPUplink

	relayInboundMu sync.RWMutex
	relayInboundCh chan []byte
)

// SetRelayTCPUplink registers the active TCP relay client for ciphertext send. Pass nil on shutdown.
func SetRelayTCPUplink(u relayTCPUplink) {
	relayTCPMu.Lock()
	defer relayTCPMu.Unlock()
	relayTCP = u
}

func activeRelayTCPUplink() relayTCPUplink {
	relayTCPMu.RLock()
	defer relayTCPMu.RUnlock()
	return relayTCP
}

func registerRelayInbound(ch chan []byte) {
	relayInboundMu.Lock()
	defer relayInboundMu.Unlock()
	relayInboundCh = ch
}

// DeliverRelayTCPInbound pushes relay→client DATA into the userspace WireGuard receive path.
func DeliverRelayTCPInbound(pkt []byte) {
	relayInboundMu.RLock()
	ch := relayInboundCh
	relayInboundMu.RUnlock()
	if ch == nil || len(pkt) == 0 {
		return
	}
	p := make([]byte, len(pkt))
	copy(p, pkt)
	select {
	case ch <- p:
	default:
		slog.Warn("relay tcp: inbound queue full, dropping packet")
	}
}
