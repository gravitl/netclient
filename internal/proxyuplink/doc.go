// Package proxyuplink wires github.com/gravitl/proxy into netclient for TCP/TLS gateway uplinks.
//
// Driven by server-published node fields (not environment variables):
//   - Client: UseTcpUplink + RelayedBy + PeerIDs.tcp_proxy_endpoint → proxy.Client + userspace Bind
//   - Gateway: TcpProxyEnabled + TcpProxyListenPort → proxy.Server + userspace Bind
//
// Linux uses userspace WireGuard when either flag is set so ciphertext can be diverted via conn.Bind.
package proxyuplink
