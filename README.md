
<p align="center">
  <a href="https://netmaker.io">
  <img src="./netclient.png" width="50%"><break/>
  </a>
</p>

<p align="center">
  <a href="https://github.com/gravitl/netmaker/releases">
    <img src="https://img.shields.io/badge/Version-0.18.5-informational?style=flat-square" />
  </a>
  <a href="https://hub.docker.com/r/gravitl/netclient/tags">
    <img src="https://img.shields.io/docker/pulls/gravitl/netclient?label=downloads" />
  </a>
  <a href="https://goreportcard.com/report/github.com/gravitl/netclient">
    <img src="https://goreportcard.com/badge/github.com/gravitl/netclient" />
  </a>
</p>

# Automated WireGuard® Management Client 

This is the client for Netmaker networks. To learn more about Netmaker, [see here](http://github.com/gravitl/netmaker).

## Installation

https://docs.netmaker.org/netclient.html#installation

## Usage

https://docs.netmaker.org/netclient.html#joining-a-network

## Join a network

With Token:  
`netclient join -t <token>`

With User (Basic Auth):  
`netclient join -n <net name> -u <username> -s api.<netmaker domain>`

With User (SSO):  
`netclient join -n <net name> -s api.<netmaker domain>`

## Commands
```
Netmaker's netclient agent and CLI to manage wireguard networks

Join, leave, connect and disconnect from netmaker wireguard networks.

Usage:
  netclient [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  connect     connect to a netmaker network
  daemon      netclient daemon
  disconnect  disconnet from a network
  gui         Starts Netclient GUI
  help        Help about any command
  install     install netclient binary and daemon
  join        join a network
  leave       leave a network
  list        display list of netmaker networks
  pull        get the latest node configuration
  uninstall   uninstall netclient
  version     Displays version information

Flags:
      --config string   use specified config file
  -h, --help            help for netclient
  -v, --verbosity int   set logging verbosity 0-4

Use "netclient [command] --help" for more information about a command.
```

For more information on the GUI, check [here](./gui/README.md)

## Disclaimer
 [WireGuard](https://wireguard.com/) is a registered trademark of Jason A. Donenfeld.

## License

Netclient's source code and all artifacts in this repository are freely available under the Apache 2.0 License, which can be found here: [LICENSE.txt](./LICENSE.txt).
