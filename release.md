# Netclient v0.20.6

## Whats New
- Support for additional init systems on linux (initd,openrc)
## What's Fixed

- Auto upgrade is fixed
- Enhanced TURN functionality
- Deprecated Proxy
- Simplified Firewall rules for added stability
     
## known issues
- Windows installer does not install WireGuard
- netclient-gui will continously display error dialog if netmaker server is offline
- Incorrect metrics against ext clients
- Host ListenPorts set to 0 after migration from 0.17.1 -> 0.20.6
- Mac IPv6 addresses/route issues
- Docker client can not re-join after complete deletion
- netclient-gui network tab blank after disconnect
