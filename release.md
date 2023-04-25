# Netclient v0.18.7

## Whats New
- internet gateways for egress
- 
## What's Fixed
- peer update improvements
- sso/basic auth registration
- auto updates
- refresh of wireguard keys
- forwarding rules to counteract docker setting default forward policy to deny
- prevent routing changes to private addresses

## known issues
- Incorrect metrics against ext clients
- Host ListenPorts set to 0 after migration from 0.17.1 -> 0.18.6
- Mac IPv6 addresses/route issues
- Docker client can not re-join after complete deletion
- netclient-gui network tab blank after disconnect

