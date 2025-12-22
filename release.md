## Netclient v1.4.0 Release Notes 🚀 

## 🚀 What’s New

### 🌍 Posture Checks (beta)

- Security feature that validates device compliance against configured policies based on device attributes such as OS, OS version, kernel version, client version, geographic location, and auto-update status.
- Supports tag-based and user group-based assignment of posture checks to specific devices or users.
- Tracks violations with configurable severity levels and provides real-time evaluation of device compliance.
- Helps ensure only compliant devices can access network resources.

### 🔁 Network Traffic Logging (alpha)

- Comprehensive network flow logging system that captures and stores network traffic metadata in ClickHouse.
- Tracks source and destination IPs, ports, protocols, bytes/packets sent/received, and connection timestamps.
- Provides API endpoints for querying flow data with filters by network, node, user, protocol, and time range.
- Enables network administrators to monitor, analyze, and audit network traffic patterns for security and troubleshooting purposes.

### 🔄 Auto Removal of Offline Peers

- Automatically removes nodes that have been offline for a configurable threshold period.
- Configurable per network with customizable timeout thresholds (in minutes).
- Supports tag-based filtering to selectively apply auto-removal to specific device groups.
- Helps maintain clean network topology by removing stale or abandoned peer connections.

### 🧭 DNS Search Domains

- Added DNS search domain functionality for simplified hostname resolution across distributed networks.

### 🖥️ New CLI Commands

- **`netclient peers`**: Display WireGuard peer information including public keys, host names, endpoints, last handshake times, traffic statistics (bytes received/sent), and allowed IPs. Supports filtering by network and JSON output format for programmatic access.

- **`netclient ping`**: Check connectivity and latency to WireGuard peers across networks. Supports filtering by network or peer name, IPv4/IPv6 address selection, configurable packet count, and JSON output format. Helps diagnose network connectivity issues and measure peer latency.


## 🧰 Improvements & Fixes

- DNS Fixes: Debian DNS configuration fix.

- Host Listen Port: Enhanced Port Configuration Logic.

- Egress Domain Updates: Fixed domain-related issues in egress configurations to ensure consistent routing behavior.

- Auto Gateway: Refresh connection metrics if no Gateway node found to update cached metrics.

## Known Issues 🐞

- netclients cannot auto-upgrade on ipv6-only machines.

- Need to optimize multi-network netclient join with enrollment key

- On systems using systemd-resolved in unlink mode, the first 3 entries in resolv.conf are used and rest are ignored. So it might cause DNS issues. Stub mode is preferred.

