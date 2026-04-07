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

// SetRelayUDPEndpoint configures the WireGuard UDP endpoint string for the relay peer so
// ciphertext to that address is sent over the TCP proxy instead of UDP. Call after
// HostPeers are populated (e.g. from startRelayTCPUplink). No-op if not using relay TCP bind.
func SetRelayUDPEndpoint(addr string) error {
	relayBindMu.Lock()
	b := relayBind
	relayBindMu.Unlock()
	if b == nil || addr == "" {
		return nil
	}
	return b.setRelay(addr)
}

// relayTCPBind wraps the default UDP bind and routes relay peer traffic through the TCP uplink.
type relayTCPBind struct {
	udp conn.Bind

	mu       sync.RWMutex
	relayStr string
	relayEp  conn.Endpoint

	inbound chan []byte
}

func newRelayTCPBind(udp conn.Bind) *relayTCPBind {
	return &relayTCPBind{udp: udp}
}

func (b *relayTCPBind) setRelay(addr string) error {
	ep, err := b.udp.ParseEndpoint(addr)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.relayEp = ep
	b.relayStr = ep.DstToString()
	return nil
}

func (b *relayTCPBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.udp.Open(port)
	if err != nil {
		return nil, 0, err
	}
	b.inbound = make(chan []byte, 256)
	registerRelayInbound(b.inbound)

	recvTCP := func(buf []byte) (int, conn.Endpoint, error) {
		pkt, ok := <-b.inbound
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(buf, pkt)
		b.mu.RLock()
		ep := b.relayEp
		b.mu.RUnlock()
		if ep == nil {
			return 0, nil, errors.New("relay tcp: relay UDP endpoint not set yet")
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
	b.mu.RLock()
	rs := b.relayStr
	b.mu.RUnlock()
	if rs != "" && ep.DstToString() == rs {
		u := activeRelayTCPUplink()
		if u != nil {
			return u.SendPacket(context.Background(), p)
		}
	}
	return b.udp.Send(p, ep)
}

func (b *relayTCPBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return b.udp.ParseEndpoint(s)
}
