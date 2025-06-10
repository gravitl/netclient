# Netclient v0.99.0

## Whats New ✨

- ACLs on Community Edition (Beta): The new version of Access Control Lists is now available in CE as a beta feature.

- Auto Sync Server Settings: Automatically propagate server configuration changes across nodes.

- DNS Search Domains on Windows: DNS search domains configuration for Windows clients.

## 🛠 Improvements & Fixes

- Optimized DNS Query Handling: Faster and more efficient internal name resolution.

- Improved Failover Handling: Enhanced stability and signaling for NAT traversal peer connections.

- User Egress Policies: More granular control over user-level outbound traffic policies.

- LAN/Private Routing Enhancements: Better detection and handling of local/private endpoint routes during peer communication.

- Stale Route Cleanup on Node Disconnect: Automatically removes outdated interface routes when nodes disconnect.

## Known Issues 🐞

- Stale Peer On The Interface, When Forced Removed From Multiple Networks At Once.
