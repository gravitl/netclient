//go:build linux || darwin || freebsd || windows
// +build linux darwin freebsd windows

package wireguard

import (
	"context"
	"errors"
	"fmt"
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

// TCPRoutedPeerIDs returns peer IDs currently mapped for gateway TCP uplink.
func TCPRoutedPeerIDs() []string {
	relayBindMu.Lock()
	b := relayBind
	relayBindMu.Unlock()
	if b == nil {
		return nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	ids := make([]string, 0, len(b.peerToEp))
	for id := range b.peerToEp {
		ids = append(ids, id)
	}
	return ids
}

// relayTCPBind wraps the default UDP bind and routes TCP-uplink peer traffic.
type relayTCPBind struct {
	udp conn.Bind

	mu sync.RWMutex
	// client mode: single relay UDP endpoint
	relayStr string // printable ip:port, also the inbound delivery key
	relayKey string // wire address, matched against Send destinations
	relayEp  conn.Endpoint
	// gateway mode
	peerToEp  map[string]string        // peerID -> printable ip:port
	peerToKey map[string]string        // peerID -> wire address
	keyToPeer map[string]string        // wire address -> peerID
	epCache   map[string]conn.Endpoint // printable ip:port -> endpoint

	inbound     chan inboundPkt
	inboundOnce sync.Once
}

func newRelayTCPBind(udp conn.Bind) *relayTCPBind {
	return &relayTCPBind{
		udp:       udp,
		peerToEp:  make(map[string]string),
		peerToKey: make(map[string]string),
		keyToPeer: make(map[string]string),
		epCache:   make(map[string]conn.Endpoint),
	}
}

// endpointKey identifies an endpoint by its wire address (IP plus port) rather
// than by DstToString: wireguard-go's WinRingEndpoint drops the return value of
// DstToString for IPv4, so on Windows every endpoint stringifies to "" and no
// divert ever matched.
func endpointKey(ep conn.Endpoint) string {
	if ep == nil {
		return ""
	}
	return string(ep.DstToBytes())
}

// resolveEndpoint parses addr and returns the endpoint together with the two
// keys it is tracked under: the wire address for Send matching and a printable
// address for inbound delivery.
func (b *relayTCPBind) resolveEndpoint(addr string) (ep conn.Endpoint, epStr, key string, err error) {
	ep, err = b.parseEndpoint(addr)
	if err != nil {
		return nil, "", "", err
	}
	key = endpointKey(ep)
	if key == "" {
		return nil, "", "", fmt.Errorf("tcp uplink: unsupported endpoint address %q", addr)
	}
	epStr = ep.DstToString()
	if epStr == "" {
		epStr = addr
	}
	return ep, epStr, key, nil
}

func (b *relayTCPBind) setClientRelay(addr string) error {
	ep, epStr, key, err := b.resolveEndpoint(addr)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.relayStr != "" {
		delete(b.epCache, b.relayStr)
	}
	b.relayEp = ep
	b.relayStr = epStr
	b.relayKey = key
	b.epCache[epStr] = ep
	return nil
}

func (b *relayTCPBind) clearClientRelay() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.relayStr != "" {
		delete(b.epCache, b.relayStr)
	}
	b.relayStr = ""
	b.relayKey = ""
	b.relayEp = nil
}

func (b *relayTCPBind) setPeerRoute(peerID, addr string) error {
	ep, epStr, key, err := b.resolveEndpoint(addr)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dropPeerRouteLocked(peerID)
	b.peerToEp[peerID] = epStr
	b.peerToKey[peerID] = key
	b.keyToPeer[key] = peerID
	b.epCache[epStr] = ep
	return nil
}

func (b *relayTCPBind) clearPeerRoute(peerID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dropPeerRouteLocked(peerID)
}

func (b *relayTCPBind) dropPeerRouteLocked(peerID string) {
	if key, ok := b.peerToKey[peerID]; ok {
		delete(b.keyToPeer, key)
		delete(b.peerToKey, peerID)
	}
	if epStr, ok := b.peerToEp[peerID]; ok {
		delete(b.epCache, epStr)
		delete(b.peerToEp, peerID)
	}
}

func (b *relayTCPBind) clearAllPeerRoutes() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.peerToEp = make(map[string]string)
	b.peerToKey = make(map[string]string)
	b.keyToPeer = make(map[string]string)
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

// endpointFor resolves an inbound packet's endpoint string, parsing and caching
// it when a live TCP session delivers packets before (or after) its route is
// registered. Sessions outlive route registration across peer updates, so a
// cache miss must not be treated as an error.
func (b *relayTCPBind) endpointFor(epStr string) (conn.Endpoint, error) {
	b.mu.RLock()
	ep := b.epCache[epStr]
	b.mu.RUnlock()
	if ep != nil {
		return ep, nil
	}
	parsed, err := b.parseEndpoint(epStr)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if existing := b.epCache[epStr]; existing != nil {
		return existing, nil
	}
	b.epCache[epStr] = parsed
	return parsed, nil
}

func (b *relayTCPBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.udp.Open(port)
	if err != nil {
		return nil, 0, err
	}
	for i := range fns {
		fns[i] = normalizeReceive(fns[i])
	}
	b.inbound = make(chan inboundPkt, tcpInQueueSize)
	b.inboundOnce = sync.Once{}
	inbound := b.inbound
	registerRelayInbound(inbound)

	// Only net.ErrClosed may be returned from here. wireguard-go's receive
	// routine sleeps 1/3s on any other error and exits permanently after 10
	// consecutive ones, which would silently kill all TCP-uplink ingress for the
	// lifetime of the device. Bad packets are dropped and accounted instead.
	recvTCP := func(buf []byte) (int, conn.Endpoint, error) {
		for {
			// Use the channel captured at Open — never read b.inbound after Close nils it
			// (receive on a nil channel blocks forever and freezes Device.Close / wg show).
			pkt, ok := <-inbound
			if !ok {
				return 0, nil, net.ErrClosed
			}
			if len(pkt.data) > len(buf) {
				tcpInOversizeDrops.note("tcp uplink: inbound packet larger than receive buffer, dropping")
				continue
			}
			ep, err := b.endpointFor(pkt.epStr)
			if err != nil {
				tcpInEndpointDrops.note("tcp uplink: cannot resolve inbound endpoint, dropping")
				continue
			}
			return copy(buf, pkt.data), ep, nil
		}
	}
	return append(fns, recvTCP), actualPort, nil
}

func (b *relayTCPBind) closeInbound() {
	b.inboundOnce.Do(func() {
		registerRelayInbound(nil)
		if b.inbound != nil {
			close(b.inbound)
			// Leave b.inbound non-nil so recvTCP's captured ch still works until close;
			// the closed channel unblocks receivers. Nil would be wrong for the capture.
		}
	})
}

// closeRelayTCPInbound unblocks the TCP ReceiveFunc before Device.Close.
func closeRelayTCPInbound() {
	relayBindMu.Lock()
	b := relayBind
	relayBindMu.Unlock()
	if b != nil {
		b.closeInbound()
	}
}

func (b *relayTCPBind) Close() error {
	b.closeInbound()
	return b.udp.Close()
}

func (b *relayTCPBind) SetMark(mark uint32) error {
	return b.udp.SetMark(mark)
}

func (b *relayTCPBind) Send(p []byte, ep conn.Endpoint) error {
	dst := endpointKey(ep)

	b.mu.RLock()
	relayKey := b.relayKey
	peerID := b.keyToPeer[dst]
	b.mu.RUnlock()

	// Never block on TLS I/O here: WireGuard holds device.net.RLock across Bind.Send.
	if relayKey != "" && dst == relayKey {
		if u := activeRelayTCPUplink(); u != nil {
			pkt := append([]byte(nil), p...)
			return enqueueTCPOut(func() {
				_ = u.SendPacket(context.Background(), pkt)
			})
		}
	}

	if peerID != "" {
		if s := activeTCPUplinkServer(); s != nil {
			// Only divert peers with a live TCP session. Pre-registered RelayedNodes
			// (or stale routes) must still use UDP so exit clients without UseTcpUplink
			// can complete handshakes.
			if s.HasSession(peerID) {
				pkt := append([]byte(nil), p...)
				id := peerID
				return enqueueTCPOut(func() {
					_ = s.SendToPeer(context.Background(), id, pkt)
				})
			}
		}
	}

	return b.udp.Send(p, rawEndpoint(ep))
}

func (b *relayTCPBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return b.parseEndpoint(s)
}

func (b *relayTCPBind) parseEndpoint(s string) (conn.Endpoint, error) {
	ep, err := b.udp.ParseEndpoint(s)
	if err != nil {
		return nil, err
	}
	return normalizeEndpoint(ep), nil
}
