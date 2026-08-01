//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package wireguard

import (
	"context"
	"errors"
	"net"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

var (
	relayBindMu sync.Mutex
	relayBind   *relayTCPBind
)

func clientRelayEndpoint() string {
	relayBindMu.Lock()
	b := relayBind
	relayBindMu.Unlock()
	if b == nil {
		return ""
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.relayStr
}

// SetRelayUDPEndpoint configures the WireGuard UDP endpoint for the client's relay/gateway peer
// so ciphertext to that address is sent over the TCP uplink instead of UDP.
func SetRelayUDPEndpoint(addr string) error {
	relayBindMu.Lock()
	b := relayBind
	relayBindMu.Unlock()
	if b == nil || addr == "" {
		return nil
	}
	return b.setClientRelay(addr)
}

// ClearClientRelay clears the client-mode TCP uplink route so packets fall back to UDP.
func ClearClientRelay() {
	relayBindMu.Lock()
	b := relayBind
	relayBindMu.Unlock()
	if b == nil {
		return
	}
	b.clearClientRelay()
}

// SetTCPPeerRoute maps a TCP-uplink client peer ID to a WG UDP endpoint string (gateway mode).
func SetTCPPeerRoute(peerID, udpEndpoint string) error {
	relayBindMu.Lock()
	b := relayBind
	relayBindMu.Unlock()
	if b == nil {
		return errors.New("tcp uplink bind not active")
	}
	return b.setPeerRoute(peerID, udpEndpoint)
}

// ClearTCPPeerRoute removes a gateway-mode peer route.
func ClearTCPPeerRoute(peerID string) {
	relayBindMu.Lock()
	b := relayBind
	relayBindMu.Unlock()
	if b != nil {
		b.clearPeerRoute(peerID)
	}
}

// ClearAllTCPPeerRoutes clears all gateway-mode peer routes.
func ClearAllTCPPeerRoutes() {
	relayBindMu.Lock()
	b := relayBind
	relayBindMu.Unlock()
	if b != nil {
		b.clearAllPeerRoutes()
	}
}

// TCPPeerEndpoint returns the UDP endpoint string registered for a TCP uplink peer ID.
func TCPPeerEndpoint(peerID string) string {
	relayBindMu.Lock()
	b := relayBind
	relayBindMu.Unlock()
	if b == nil {
		return ""
	}
	return b.peerEndpoint(peerID)
}

// relayTCPBind wraps the default UDP bind and routes TCP-uplink peer traffic.
type relayTCPBind struct {
	udp conn.Bind

	mu sync.RWMutex
	// client mode: single relay UDP endpoint
	relayStr string
	relayEp  conn.Endpoint
	// gateway mode: peerID -> endpoint string; endpoint string -> peerID
	peerToEp map[string]string
	epToPeer map[string]string
	epCache  map[string]conn.Endpoint

	inbound chan inboundPkt
}

func newRelayTCPBind(udp conn.Bind) *relayTCPBind {
	return &relayTCPBind{
		udp:      udp,
		peerToEp: make(map[string]string),
		epToPeer: make(map[string]string),
		epCache:  make(map[string]conn.Endpoint),
	}
}

func (b *relayTCPBind) setClientRelay(addr string) error {
	ep, err := b.udp.ParseEndpoint(addr)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.relayStr != "" {
		delete(b.epCache, b.relayStr)
	}
	b.relayEp = ep
	b.relayStr = ep.DstToString()
	b.epCache[b.relayStr] = ep
	return nil
}

func (b *relayTCPBind) clearClientRelay() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.relayStr != "" {
		delete(b.epCache, b.relayStr)
	}
	b.relayStr = ""
	b.relayEp = nil
}

func (b *relayTCPBind) setPeerRoute(peerID, addr string) error {
	ep, err := b.udp.ParseEndpoint(addr)
	if err != nil {
		return err
	}
	epStr := ep.DstToString()
	b.mu.Lock()
	defer b.mu.Unlock()
	if old, ok := b.peerToEp[peerID]; ok {
		delete(b.epToPeer, old)
		delete(b.epCache, old)
	}
	b.peerToEp[peerID] = epStr
	b.epToPeer[epStr] = peerID
	b.epCache[epStr] = ep
	return nil
}

func (b *relayTCPBind) clearPeerRoute(peerID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if old, ok := b.peerToEp[peerID]; ok {
		delete(b.epToPeer, old)
		delete(b.epCache, old)
		delete(b.peerToEp, peerID)
	}
}

func (b *relayTCPBind) clearAllPeerRoutes() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.peerToEp = make(map[string]string)
	b.epToPeer = make(map[string]string)
	// keep client relay endpoint in epCache if set
	kept := make(map[string]conn.Endpoint)
	if b.relayStr != "" && b.relayEp != nil {
		kept[b.relayStr] = b.relayEp
	}
	b.epCache = kept
}

func (b *relayTCPBind) peerEndpoint(peerID string) string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.peerToEp[peerID]
}

func (b *relayTCPBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.udp.Open(port)
	if err != nil {
		return nil, 0, err
	}
	b.inbound = make(chan inboundPkt, 256)
	registerRelayInbound(b.inbound)

	recvTCP := func(buf []byte) (int, conn.Endpoint, error) {
		pkt, ok := <-b.inbound
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(buf, pkt.data)
		b.mu.RLock()
		ep := b.epCache[pkt.epStr]
		b.mu.RUnlock()
		if ep == nil {
			return 0, nil, errors.New("tcp uplink: inbound endpoint missing")
		}
		return n, ep, nil
	}
	return append(fns, recvTCP), actualPort, nil
}

func (b *relayTCPBind) Close() error {
	registerRelayInbound(nil)
	if b.inbound != nil {
		ch := b.inbound
		b.inbound = nil
		close(ch)
	}
	return b.udp.Close()
}

func (b *relayTCPBind) SetMark(mark uint32) error {
	return b.udp.SetMark(mark)
}

func (b *relayTCPBind) Send(p []byte, ep conn.Endpoint) error {
	dst := ep.DstToString()

	b.mu.RLock()
	relayStr := b.relayStr
	peerID := b.epToPeer[dst]
	b.mu.RUnlock()

	// Never block on TLS I/O here: WireGuard holds device.net.RLock across Bind.Send.
	if relayStr != "" && dst == relayStr {
		if u := activeRelayTCPUplink(); u != nil {
			pkt := append([]byte(nil), p...)
			return enqueueTCPOut(func() {
				_ = u.SendPacket(context.Background(), pkt)
			})
		}
	}

	if peerID != "" {
		if s := activeTCPUplinkServer(); s != nil {
			pkt := append([]byte(nil), p...)
			id := peerID
			return enqueueTCPOut(func() {
				_ = s.SendToPeer(context.Background(), id, pkt)
			})
		}
	}

	return b.udp.Send(p, ep)
}

func (b *relayTCPBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return b.udp.ParseEndpoint(s)
}
