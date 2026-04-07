// Package proxyuplink wires github.com/gravitl/proxy into netclient for TCP/TLS relay uplinks.
//
// When NC_RELAY_TCP_UPLINK_ADDR is set:
//   - Linux netclient uses userspace WireGuard (wireguard-go) instead of kernel WG so relay
//     traffic can be bound via conn.Bind to the TCP proxy (see ForceUserspaceWireGuard).
//   - The daemon starts a proxy.Client to the relay. Inbound ciphertext is delivered to
//     SetInboundHandler; complete the path by wiring conn.Bind to SendPacket / the handler.
//
// Relay/gateway processes that terminate the TCP uplink need a similar userspace (or inject)
// path to feed HandleInboundPacket data into WireGuard; kernel-only relay cannot consume TCP
// frames without that integration.
package proxyuplink
