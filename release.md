# Netclient v0.20.0

## Whats New

-- TURN improvements
    nodes behind asymetrical/double NAT will use TURN to communicate
- dependency updates

## What's Fixed
- endpoint detectiono



## known issues
- netclient-gui (windows) will display an erroneous error dialog when joining a network (can be ignored)
- netclient-gui will continously display error dialog if netmaker server is offline
- Incorrect metrics against ext clients
- Host ListenPorts set to 0 after migration from 0.17.1 -> 0.20.0
- Mac IPv6 addresses/route issues
- Docker client can not re-join after complete deletion
- netclient-gui network tab blank after disconnect

