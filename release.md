# Netclient v0.19.0

## Whats New

- Unprivilged GUI
    netclient-gui runs without root/administrator permissions; requires netclient daemon 
- TURN
    nodes behind asymetrical/double NAT will use TURN to communicate
- dependency updates

## What's Fixed
- unbiased random string
- CI updates
- creation of explicit server/peer routes for internet gateways
- firewall detection
- nftables forwarding


## known issues
- netclient-gui (windows) will display an erroneous error dialog when joining a network (can be ignored)
- netclient-gui will continously display error dialog if netmaker server is offline
- Incorrect metrics against ext clients
- Host ListenPorts set to 0 after migration from 0.17.1 -> 0.18.6
- Mac IPv6 addresses/route issues
- Docker client can not re-join after complete deletion
- netclient-gui network tab blank after disconnect

