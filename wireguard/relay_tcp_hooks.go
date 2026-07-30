package wireguard

import (
	"context"
	"sync"

	"golang.org/x/exp/slog"
)

// needTCPUplinkBind is set from proxyuplink.NeedsUserspaceWG before iface create.
var needTCPUplinkBind bool

// SetNeedTCPUplinkBind marks that userspace WireGuard + TCP bind should be used.
func SetNeedTCPUplinkBind(v bool) {
	needTCPUplinkBind = v
}

func relayTCPUserspaceNeeded() bool {
	return needTCPUplinkBind
}

type inboundPkt struct {
	data []byte
	epStr string
}

// relayTCPUplink is implemented by proxyuplink.Manager (SendPacket).
type relayTCPUplink interface {
	SendPacket(ctx context.Context, pkt []byte) error
}

// tcpUplinkServer is implemented by proxyuplink.ServerManager (SendToPeer).
type tcpUplinkServer interface {
	SendToPeer(ctx context.Context, peerID string, pkt []byte) error
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
	relayInboundMu.RLock()
	ch := relayInboundCh
	relayInboundMu.RUnlock()
	if ch == nil || epStr == "" || len(pkt) == 0 {
		return
	}
	p := make([]byte, len(pkt))
	copy(p, pkt)
	select {
	case ch <- inboundPkt{data: p, epStr: epStr}:
	default:
		slog.Warn("tcp uplink: inbound queue full, dropping packet")
	}
}

// DeliverRelayTCPInbound pushes gateway→client DATA into userspace WG (client mode).
func DeliverRelayTCPInbound(pkt []byte) {
	epStr := clientRelayEndpoint()
	if epStr == "" {
		slog.Warn("tcp uplink: relay endpoint not set; dropping inbound")
		return
	}
	pushInbound(epStr, pkt)
}

// DeliverTCPInbound pushes TCP→WG ciphertext as if received from udpEndpoint (gateway mode).
func DeliverTCPInbound(udpEndpoint string, pkt []byte) {
	pushInbound(udpEndpoint, pkt)
}
