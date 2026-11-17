# Netclient v1.8.0 Release Notes 🚀

## 🚀 What’s New

### 💻 All-New Desktop Apps

Completely redesigned **Netmaker Desktop Apps** powered by netclient for a faster, stable connection experience.

- Now available to **CE users** as well (previously limited to Pro/EE).
- **Peer-to-peer by default** — desktop devices join the mesh with direct WireGuard peering (not gateway-only), for lower latency and better connectivity.
- Separate **desktop** and **headless** builds (`-tags desktop`) so GUI session, tray, and device APIs stay isolated from server/daemon installs.
- Fresh UI and connection flow for connecting to networks and exit nodes.
- Improved status visibility for tunnel state and exit modes.
- **Auto Exit** — when enabled on a network (`auto_select_exit_node`), desktop/user devices are automatically assigned an allowed internet exit (nearest available) when they connect; users can still switch exits when permitted.

### 🔐 Managed Access with Netmaker SSH

Secure, managed SSH access via netclient’s embedded SSH/SCP/SFTP server — without opening inbound SSH on the public internet.

- When the host has **Manage SSH** enabled, netclient starts the embedded SSH server and listens on the mesh.
- Access is limited to peers that can reach the host over Netmaker.
- Useful for admin access, file transfer, and operational workflows on enrolled devices.

### 🪟 Windows Egress Support

Windows hosts can now act as **egress gateways**.

- Advertise egress ranges and route mesh traffic to attached LAN/site networks on Windows.
- Uses **Hyper-V NetNat** for egress NAT and **WFP** for peer/host and egress ACL enforcement.
- Improved multi-network egress routing (correct nexthop / on-link handling on Windows).

### 🔀 Bypass Egress Routes

Honors the server **`bypass_egress_routes`** option on internet egress so traffic to other (site) egress destinations does not hairpin through the internet exit.

- **Why:** Without bypass, clients using an internet exit often send site-egress traffic up to the exit node and back out again (hairpin), adding latency and load.
- When bypass is enabled, allowed site egress stays as **direct WireGuard peers** so traffic to those sites flows peer-to-peer instead of bending through the exit.



---

## 🧰 Improvements & Fixes

### **Desktop / Exit Nodes**
- Stop Desktop exit flap on `ChangeDefaultGw=false` races; finish deferred IGW teardown when select/restore ends.
- Preserve internet-exit routes across connect/disconnect and iface rebuilds; correct multi-net exit source selection on Darwin/Windows.
- Defer exit latency probes until after connect so listing stays non-blocking; allow UI exit list while disconnected for restore.
- Keep host enrollment on Desktop logout; transfer ownership on re-login; recover orphaned `:53` listeners after login/logout.

### **Auto-Relay**
- Lower CPU use for auto-relay; keep auto-relay on pull by default.
- `netclient pull --reset-connections` for a one-shot peer/auto-relay reset; one-shot auto-relay scan after peers land (handshake grace).

### **Egress / Firewall**
- Reinstall egress after iface rebuild; skip unchanged egress on peer update; clear leftover Windows on-link routes.
- Windows multi-net egress via GW nexthop (parity with Linux Src/Gw behavior).
- nftables metrics port encoded in network order; IPv6 NAT handling for iptables and nftables.
- Default-deny inbound on Desktop (Darwin pf); skip server FW rules where appropriate.


### **Auth / Session**
- Re-register once when session pull returns unauthorized.
- Use user JWT for owned-device control-plane auth; deprecate join-with-user-auth flows.
- ECDH-derived AES keys for decrypting server messages.

### **Endpoint / Listen Port**
- Refresh the public listen port independently of a static endpoint (STUN for dynamic port even when the endpoint is static, and vice versa).
- Skip hole punch only when both endpoint and port are static.
- Skip STUN and IP detection for relayed devices.

### **Build**
- Separate desktop and headless build tags; Go toolchain updated to **1.26.0**.


---

## 🐞 Known Issues

- **IPv6-only machines**  
  Netclients cannot currently **auto-upgrade** on IPv6-only systems.

- **Multi-network join performance**  
  Multi-network netclient joins using an **enrollment key** still require optimization.

- **systemd-resolved DNS limitation**  
  On systems using **systemd-resolved in uplink mode**, only the **first 3 entries** in `resolv.conf` are honored; additional entries are ignored. This may cause DNS resolution issues. **Stub mode is recommended**.
