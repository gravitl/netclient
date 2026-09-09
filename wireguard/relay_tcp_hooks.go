package wireguard

import (
	"context"
	"sync"
	"sync/atomic"
)

// needTCPUplinkBind is set from proxyuplink.NeedsUserspaceWG before iface create.
var needTCPUplinkBind atomic.Bool

// SetNeedTCPUplinkBind marks that userspace WireGuard + TCP bind should be used.
func SetNeedTCPUplinkBind(v bool) {
	needTCPUplinkBind.Store(v)
}

func relayTCPUserspaceNeeded() bool {
	return needTCPUplinkBind.Load()
}

type inboundPkt struct {
	data  []byte
	epStr string
}

// relayTCPUplink is implemented by proxyuplink.Manager (SendPacket).
type relayTCPUplink interface {
	SendPacket(ctx context.Context, pkt []byte) error
}

// tcpUplinkServer is implemented by proxyuplink.ServerManager.
type tcpUplinkServer interface {
	SendToPeer(ctx context.Context, peerID string, pkt []byte) error
	HasSession(peerID string) bool
}

var (
	relayTCPMu sync.RWMutex
	relayTCP   relayTCPUplink

	tcpServerMu sync.RWMutex
	tcpServer   tcpUplinkServer

	relayInboundMu sync.RWMutex
	relayInboundCh chan inboundPkt
)

// SetRelayTCPUplink registers the active TCP uplink client. Pass nil on shutdown.
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

// SetTCPUplinkServer registers the gateway TCP uplink server. Pass nil on shutdown.
func SetTCPUplinkServer(s tcpUplinkServer) {
	tcpServerMu.Lock()
	defer tcpServerMu.Unlock()
	tcpServer = s
}

func activeTCPUplinkServer() tcpUplinkServer {
	tcpServerMu.RLock()
	defer tcpServerMu.RUnlock()
	return tcpServer
}

func registerRelayInbound(ch chan inboundPkt) {
	relayInboundMu.Lock()
	defer relayInboundMu.Unlock()
	relayInboundCh = ch
}

func pushInbound(epStr string, pkt []byte) {
	if epStr == "" || len(pkt) == 0 {
		return
	}
	p := make([]byte, len(pkt))
	copy(p, pkt)
	// Read lock only: this runs per packet, so an exclusive lock here serialises
	// every inbound packet of the tunnel.
	relayInboundMu.RLock()
	defer relayInboundMu.RUnlock()
	ch := relayInboundCh
	if ch == nil {
		return
	}
	select {
	case ch <- inboundPkt{data: p, epStr: epStr}:
	default:
		tcpInQueueDrops.note("tcp uplink: inbound queue full, dropping packet")
	}
}

// DeliverRelayTCPInbound pushes gateway→client DATA into userspace WG (client mode).
func DeliverRelayTCPInbound(pkt []byte) {
	epStr := clientRelayEndpoint()
	if epStr == "" {
		tcpInEndpointDrops.note("tcp uplink: relay endpoint not set; dropping inbound")
		return
	}
	pushInbound(epStr, pkt)
}

// DeliverTCPInbound pushes TCP→WG ciphertext as if received from udpEndpoint (gateway mode).
func DeliverTCPInbound(udpEndpoint string, pkt []byte) {
	pushInbound(udpEndpoint, pkt)
}
