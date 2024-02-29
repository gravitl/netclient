# Netclient v0.23.0

## Whats New ✨

- Revamp of internet gateways: hosts and clients can now use internet gateways! More info [here](https://docs.netmaker.io/pro/internet-gateways.html)
  On community edition, internet gateways for clients can be accessed via the Remote Access tab.
- Support for userspace wireguard. You can now run Netclient on Linux machines without the WireGuard kernel module.

## What's Fixed/Improved 🛠

- Fixed ENDPOINT environment variable for Docker
- Stability fixes
- Deprecated Netclient GUI

## Known Issues 🐞

- Windows installer does not install WireGuard
- Mac IPv6 addresses/route issues
- Docker client can not re-join after complete deletion
