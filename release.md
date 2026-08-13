# Netclient v1.6.0 Release Notes 🚀

## 🚀 What’s New

### 🔁 Site-to-Site ACLs (Beta)

Define ACL policies that permit traffic between egress endpoints across networks.

- Build site-to-site rules between egress resources on different networks.
- Combine egress resources, nodes, and specific IPs in a single policy.
- Site-to-site rules are emitted alongside device-mesh rules without key collisions.


### 🛡️ Egress ACLs with IP Restriction

ACL policies can now target **individual IPs** inside an egress range using the `ip` ACL target type.

- Restrict access to specific hosts within a larger egress CIDR.
- Validate that selected IPs fall within the referenced egress range at policy create/update time.
- Mix egress resources, nodes, tags, and individual IPs in the same policy.

### 🔐 Registration & Join UX

Host registration over OAuth/basic auth now returns **clear websocket close reasons** on failure (auth errors, missing access, posture violations, and server errors).

---

## 🧰 Improvements & Fixes

### **Egress**
- Added **LAN-to-VPN masquerade** rules for iptables and nftables egress endpoints.
- Egress route filtering now applies only on **exact CIDR matches**, avoiding unintended route conflicts.

### **DNS**
- Fixed split-DNS handling across Linux DNS config managers (openresolv, resolvconf, and file-based).
- Added fallback nameserver seeding when no DNS response is available.
- Improved Windows DNS interface metric and configuration handling.

### **Internet Gateways**
- Internet Gateway health checks now validate pull data against the **IGW monitor IP**.
- Fixed peer iteration to loop over **netclient peers** instead of device peers.

### **Reliability**
- Null-terminate network interfaces to prevent configuration edge cases.
- Skip config reset when the WireGuard interface does not exist.
- Endpoint caches are reset safely using `sync.Map.Clear()`.
- Metrics collection is now triggered on demand.

### **Schema Migration**
- Updated for Netmaker v1.6.0 **nodes schema migration** compatibility.


---

## 🐞 Known Issues

- **IPv6-only machines**  
  Netclients cannot currently **auto-upgrade** on IPv6-only systems.

- **Multi-network join performance**  
  Multi-network netclient joins using an **enrollment key** still require optimization.

- **systemd-resolved DNS limitation**  
  On systems using **systemd-resolved in uplink mode**, only the **first 3 entries** in `resolv.conf` are honored; additional entries are ignored. This may cause DNS resolution issues. **Stub mode is recommended**.

