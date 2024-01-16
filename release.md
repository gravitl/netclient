# Netclient v0.22.0

## Whats New
- MQ fallback
- Revamp of internet gateways
- Use CoreDNS for DNS resolution
- DNS is no longer managed with OS hosts file (/etc/hosts file)
- Deprecating TURN in favour of failover hosts on Pro

## What's Fixed
- windows GUI prompt for server connection closed is fixed
- Fixed client version auto upgrades, works on all supported OS
- DNS Entries Management
- Handled nil endpoint on peers
## known issues
- Windows installer does not install WireGuard
- netclient-gui will continously display error dialog if netmaker server is offline
- Mac IPv6 addresses/route issues
- Docker client can not re-join after complete deletion
- netclient-gui network tab blank after disconnect
