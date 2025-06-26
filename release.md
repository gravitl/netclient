# Netclient v1.0.0

## Whats New ✨

- Gateways Unified: Internet Gateways are now merged into the general Gateway feature and available in Community Edition.

- Site-to-Site over IPv6: IPv4 site-to-site communication over IPv6 Netmaker overlay tunnels.

## 🛠 Improvements & Fixes

- Auto-Sync DNS Configs: Multi-network DNS configurations now sync automatically between server and clients.

- Stability Fixes: Improved connection reliability for nodes using Internet Gateways.

- LAN/Private Routing Enhancements: Smarter detection and handling of local/private routes, improving peer-to-peer communication in complex network environments.

## Known Issues 🐞

- Inaccurate uptime info in metrics involving ipv4-only and ipv6-only traffic

- netclients cannot auto-upgrade on ipv6-only machines.

- Need to optimize multi-network netclient join with enrollment key

- Stale Peer On The Interface, When Forced Removed From Multiple Networks At Once.
