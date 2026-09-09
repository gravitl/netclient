//go:build linux || darwin || freebsd || windows
// +build linux darwin freebsd windows

package wireguard

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

// muteEndpoint mimics wireguard-go's Windows WinRingEndpoint, whose DstToString
// returns "" for IPv4.
type muteEndpoint netip.AddrPort

func (muteEndpoint) ClearSrc()            {}
func (muteEndpoint) SrcToString() string  { return "" }
func (muteEndpoint) DstToString() string  { return "" }
func (e muteEndpoint) DstIP() netip.Addr  { return netip.AddrPort(e).Addr() }
func (muteEndpoint) SrcIP() netip.Addr    { return netip.Addr{} }
func (e muteEndpoint) DstToBytes() []byte { return dstBytes(netip.AddrPort(e)) }

func dstBytes(ap netip.AddrPort) []byte {
	b := ap.Addr().AsSlice()
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, ap.Port())
	return append(b, port...)
}

type muteBind struct{ conn.Bind }

func (muteBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return muteEndpoint(ap), nil
}

func TestRelayRoutesKeyOnWireAddress(t *testing.T) {
	b := newRelayTCPBind(muteBind{})

	if err := b.setClientRelay("203.0.113.7:51821"); err != nil {
		t.Fatalf("setClientRelay: %v", err)
	}
	if err := b.setPeerRoute("peer-a", "198.51.100.3:51820"); err != nil {
		t.Fatalf("setPeerRoute: %v", err)
	}

	relay, err := b.ParseEndpoint("203.0.113.7:51821")
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	if got := endpointKey(relay); got != b.relayKey {
		t.Errorf("relay endpoint does not match the divert key: %q vs %q", got, b.relayKey)
	}

	peer, err := b.ParseEndpoint("198.51.100.3:51820")
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	if got := b.keyToPeer[endpointKey(peer)]; got != "peer-a" {
		t.Errorf("peer endpoint routed to %q, want peer-a", got)
	}

	// Endpoints with no printable form still get a usable inbound key.
	if b.relayStr != "203.0.113.7:51821" {
		t.Errorf("relay inbound key = %q", b.relayStr)
	}
	if _, err := b.endpointFor(b.relayStr); err != nil {
		t.Errorf("endpointFor(%q): %v", b.relayStr, err)
	}

	b.clearPeerRoute("peer-a")
	if len(b.keyToPeer) != 0 || len(b.peerToKey) != 0 || len(b.peerToEp) != 0 {
		t.Errorf("clearPeerRoute left state behind: %v %v %v", b.keyToPeer, b.peerToKey, b.peerToEp)
	}
	if _, ok := b.epCache[b.relayStr]; !ok {
		t.Error("clearPeerRoute evicted the client relay endpoint")
	}
}
