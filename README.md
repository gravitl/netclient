
<p align="center">
  <a href="https://netmaker.io">
  <img src="./netclient.png" width="50%"><break/>
  </a>
</p>

<p align="center">
  <a href="https://github.com/gravitl/netmaker/releases">
    <img src="https://img.shields.io/badge/Version-0.16.1-informational?style=flat-square" />
  </a>
  <a href="https://hub.docker.com/r/gravitl/netclient/tags">
    <img src="https://img.shields.io/docker/pulls/gravitl/netclient?label=downloads" />
  </a>
  <a href="https://goreportcard.com/report/github.com/gravitl/netclient">
    <img src="https://goreportcard.com/badge/github.com/gravitl/netclient" />
  </a>
</p>

# The Netmaker client 

## Installation

https://docs.netmaker.org/netclient.html#installation

## Usage

https://docs.netmaker.org/netclient.html#joining-a-network

### Join a network

With Token:  
`netclient join -t <token>`

With User (Basic Auth):  
`netclient join -n <net name> -u <username> -s api.<netmaker domain>`

With User (SSO):  
`netclient join -n <net name> -s api.<netmaker domain>`

### Helper Functions
`netclient help`  
`netclient list`  
`wg show`  
(on linux) `systemctl status netclient`

### Connect / Disconnect from Network
`netclient connect -n <network>`  
`netclient disconnect -n <network>`

### Leave Network
`netclient leave -n <network>`

## Uninstall

`netclient uninstall`

## Disclaimer
 [WireGuard](https://wireguard.com/) is a registered trademark of Jason A. Donenfeld.

## License

Netmaker's source code and all artifacts in this repository are freely available. All versions are published under the Server Side Public License (SSPL), version 1, which can be found here: [LICENSE.txt](./LICENSE.txt).
