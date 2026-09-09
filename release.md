# Netclient v1.7.0 Release Notes 🚀

## 🚀 What’s New

### 🏢 Multi-Tenancy Support

Netclient is tenant-aware for Netmaker MSP / multi-tenant deployments.

- Sends `X-Tenant-ID` on API requests so host actions are scoped to the correct tenant.
- Prevents registering into a different tenant on a server the host is already joined to.
- Uninstall, leave, and host cleanup use the correct token and tenant context; switching servers updates tenant state cleanly.

### 🔌 TCP Proxy / WSS Uplink

Reach the mesh when UDP is blocked by tunneling WireGuard over a **TCP/WSS uplink** to a gateway.

- Gateways can enable a TCP proxy listener (`tcp_proxy_enabled`, listen port/addr, TLS mode).
- Relayed clients dial the gateway over WSS (`wss://…/uplink/v1`) and authenticate with WireGuard key proofs.
- Supports **self-signed** and **reverse-proxy / externally terminated TLS** modes.
- Userspace WireGuard bind routes uplink peers through the proxy; disabling TCP uplink returns to kernel WireGuard without hanging.

### 📱 MDM Posture Collection

Netclient collects device identity for **MDM posture checks** and reports compliance status.

- Gathers hostname, serial, hardware UUID, and Entra device ID (platform-specific collectors for Linux, macOS, and Windows).
- Sets MDM posture fields on registration and publishes identity for server-side Intune / Jamf / JumpCloud / Iru evaluation.
- New CLI: `netclient posture status` (server-evaluated results) and `netclient posture identity` (local identity snapshot).

### 🌐 Dual-Stack Exit Node Routing

Internet / exit-node routing now supports **IPv4 and IPv6** together.

- Dual-stack default routes and per-family gateway detection (including Windows default-gateway lookup by IP family).
- Exit-node UI/API fields wired through for dual-stack internet gateways.
- IPv6 NAT / masquerade rules for iptables and nftables egress endpoints.


---

## 🧰 Improvements & Fixes

### **Internet Gateways / Exit Routes**
- Reapply exit routes after IGW monitor goes unhealthy and on `ReplacePeers` peer updates.
- Improved IGW monitor status management and thread safety; don’t start the monitor with an empty gateway peer.

### **Egress / Firewall**
- Fixed nftables port rules and restored egress MASQUERADE on the default interface (keep primary masquerade; skip only LAN-to-VPN SNAT when egress uses the WAN iface).
- IPv6 NAT handling for iptables and nftables.

### **Endpoint / Listen Port**
- Refresh the public listen port independently of a static endpoint (STUN for dynamic port even when the endpoint is static, and vice versa).
- Skip hole punch only when both endpoint and port are static.

### **Build**
- Go toolchain updated to **1.26.0**.


---

## 🐞 Known Issues

- **IPv6-only machines**  
  Netclients cannot currently **auto-upgrade** on IPv6-only systems.

- **Multi-network join performance**  
  Multi-network netclient joins using an **enrollment key** still require optimization.

- **systemd-resolved DNS limitation**  
  On systems using **systemd-resolved in uplink mode**, only the **first 3 entries** in `resolv.conf` are honored; additional entries are ignored. This may cause DNS resolution issues. **Stub mode is recommended**.
