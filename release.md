# Netclient v0.18.5

## Whats New
- Client will automatically clean up servers/nodes if it detects attempted unauthorized access against a server
- Default proxy mode (propogated from server)

## What's Fixed
- Interface data collected on registration
- Bug around relay calculations fixed
- Potential nil pointer addressed
- Migration reworked
- Metric collection fixed between nodes
## known issues
- Incorrect metrics against ext clients
- Host ListenPorts set to 0 after migration from 0.17.1 -> 0.18.4
- Mac IPv6 addresses/route issues
- Docker client can not re-join after complete deletion

