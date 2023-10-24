# Netclient v0.21.2

## Whats New
- Additional args added to register cmd to set from client side
- Additional args that can be set on docker netclient
- netclient push cmd, to update certain host fields from client side
- Endpoint detection on network changes
- Upgrade client version to match server from UI
## What's Fixed
- Improved TURN connectivity
- Fixed random port issue on freeBSD
- Fixed zombie node issue
- Fixed freeBSD panic while removing host from network

## known issues
- Windows installer does not install WireGuard
- netclient-gui will continously display error dialog if netmaker server is offline
- Mac IPv6 addresses/route issues
- Docker client can not re-join after complete deletion
- netclient-gui network tab blank after disconnect
