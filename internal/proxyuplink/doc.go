// Package proxyuplink adapts netclient to gravitl/proxy WSS uplink.
//
//   - Client: UseTcpUplink + RelayedBy + PeerIDs.tcp_proxy_endpoint (wss://…/uplink/v1)
//     → uplink.Client + userspace Bind
//   - Gateway: TcpProxyEnabled + TcpProxyListenPort + TcpProxyTLSMode
//     → uplink.Server (selfsigned WSS or proxy-mode WS) + userspace Bind
package proxyuplink
