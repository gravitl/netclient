## Netclient v1.2.0 Release Notes 🚀 

## 🚀 What’s New

### 🌍 Auto-Relays (formerly Failovers)

- Failovers are now Auto-Relays with High Availability (HA) support.

- Enables global routing optimization based on real-time latency between peers across regions.

### 🔁 Gateway High Availability

- Gateways can now automatically assign peer relays and fallback to healthy nodes when primary gateways become unavailable.

### 🌐 Egress HA with Latency-Aware Routing

- Egress gateways now dynamically select the optimal route based on latency, ensuring faster and more resilient connectivity.

### 🧭 DNS Search Domains

- Added DNS search domain functionality for simplified hostname resolution across distributed networks.


## 🧰 Improvements & Fixes

- Metrics Enrichment: Enhanced uptime and connection-status data.

- DNS Control Fixes: Fixed toggle behavior for enabling/disabling Netmaker DNS on hosts.

- DNS Config Update And Cleanup Handling.

- Egress Domain Updates: Fixed domain-related issues in egress configurations to ensure consistent routing behavior.

## Known Issues 🐞

- WireGuard DNS issue on Ubuntu 24.04 and some other newer Linux distributions. The issue is affecting the Netmaker Desktop, previously known as the Remote Access Client (RAC), and the plain WireGuard external clients. Workaround can be found here https://help.netmaker.io/en/articles/9612016-extclient-rac-dns-issue-on-ubuntu-24-04.

- netclients cannot auto-upgrade on ipv6-only machines.

- Need to optimize multi-network netclient join with enrollment key

