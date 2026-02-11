## Netclient v1.5.0 Release Notes 🚀 

## 🚀 What’s New

### 🔁 Overlapping Egress Ranges (beta)

- Virtual NAT mode enables multiple egress routers to share overlapping IP ranges by assigning each egress a virtual range from a configurable pool.
- Configurable per-network IPv4 pool and site prefix length for virtual range allocation.
- Eliminates routing conflicts when multiple sites need to egress the same destination CIDRs (e.g., multiple offices routing to the same cloud VPC).
- Supports both direct NAT and virtual NAT modes for flexible egress configurations.


### 🧭 macOS Local DNS Resolver

- Darwin netclients now run their own local DNS resolver.

    #### Benefits

    - More consistent DNS resolution

    - Improved compatibility with macOS networking stack

    - Reduced dependency on system DNS behavior

### 🌐 Internet Gateways on macOS

- Darwin netclients can now:

    - Use Internet Gateways

    - Participate in fully routed internet traffic

    - This brings feature parity closer to Linux and Windows clients.


## 🧰 Improvements & Fixes

**DNS:**

- Debian DNS configuration fix

- Improved Windows DNS management

**GeoLocation:**

 - Consolidated IP location API usage

 - Added fallback mechanisms

**Windows:**

- Improved logging

- Fixed installer issues

- Version command corrections

- Better adapter error handling

**LAN Routing:**

- Added configurable interface exclusion

- Fixes Kubernetes endpoint detection conflicts

## Known Issues 🐞

- netclients cannot auto-upgrade on ipv6-only machines.

- Need to optimize multi-network netclient join with enrollment key

- On systems using systemd-resolved in uplink mode, the first 3 entries in resolv.conf are used and rest are ignored. So it might cause DNS issues. Stub mode is preferred.

