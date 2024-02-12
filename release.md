# Netclient v0.23.0

## Whats New
- MQ fallback
- Revamp of internet gateways
- Use CoreDNS for DNS resolution
- DNS is no longer managed with OS hosts file (/etc/hosts file)
- Deprecating TURN in favour of failover hosts on Pro

## What's Fixed
- Fix issues with `server` subcommand
- Fixed edge case with upgrading
- Scalability issues

## Known Issues
- Windows installer does not install WireGuard
- Mac IPv6 addresses/route issues
- Docker client can not re-join after complete deletion
