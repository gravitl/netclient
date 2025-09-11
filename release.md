# Netclient v1.1.0

## What’s New ✨ 

- Egress Domain-Based Routing – Route traffic based on domain names, not just network CIDRs.

- DNS Nameservers with Match Domain Functionality – Fine-grained DNS resolution control per domain.

- Device Approval Workflow – Require admin approval before devices can join a network.


## Improvements & Fixes 🛠 

- Access Control Lists (ACLs): Enhanced functionality and flexibility.

- Stability Enhancements: More reliable connections for nodes using Internet Gateways.

- DNS: Linux DNS Config Fixes

- Egress HA: Optimised Egress HA routing.

## Known Issues 🐞

- Inaccurate uptime info in metrics involving ipv4-only and ipv6-only traffic

- netclients cannot auto-upgrade on ipv6-only machines.

- Need to optimize multi-network netclient join with enrollment key

- Stale Peer On The Interface, When Forced Removed From Multiple Networks At Once.
