# Netclient v0.18.3

## Whats New

## What's Fixed
- More efficient Windows daemon handling
- Better peer route setting on clients
- Some commands involving the message queue on client have been fixed
- NFTables masquerading issue
- Some logging has been adjusted
- Migrations on Linux work for 0.17.x - 0.18.3
- Registration by enrollment key on client GUI
- 
## known issues
- Network interface routes may be removed after sometime/unintended network update
- Caddy does not handle netmaker exporter well for EE
- Incorrect latency on metrics (EE)
- Swagger docs not up to date
- Lengthy delay when you create an ext client
- issues connecting over IPv6 on Macs
- Nodes on same local network may not always connect
- Netclient GUI shows egress range(s) twice
- DNS entries are not sent after registration with EnrollmentKeys
- If you do NOT set STUN_LIST on server, it could lead to strange behavior on client
