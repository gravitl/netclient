package networking

import (
	"fmt"
	"net"
	"strings"

	"github.com/gravitl/netclient/cache"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/nmproxy/stun"
)

var (
	foundIPSet = make(map[string]struct{}, 0)
	addresses  = []net.IPNet{}
)

// StoreServerAddresses - given a server,
// find all the addresses associated with it and store in cache
func StoreServerAddresses(server *config.Server) {
	if server == nil {
		return
	}

	ips, _ := net.LookupIP(server.Name) // handle server base domain
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			processIPv4(ipv4)
		} else if ipv6 := ip.To16(); ipv6 != nil {
			processIPv6(ipv6)
		}
	}

	ips, _ = net.LookupIP(server.API) // handle server api
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			processIPv4(ipv4)
		} else if ipv6 := ip.To16(); ipv6 != nil {
			processIPv6(ipv6)
		}
	}

	broker := server.Broker
	brokerParts := strings.Split(broker, "//")
	if len(brokerParts) > 1 {
		broker = brokerParts[1]
	}

	ips, _ = net.LookupIP(broker) // handle server broker
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			processIPv4(ipv4)
		} else if ipv6 := ip.To16(); ipv6 != nil {
			processIPv6(ipv6)
		}
	}

	stunList := stun.StunServers
	for i := range stunList {
		stunServer := stunList[i]
		ips, err := net.LookupIP(stunServer.Domain) // handle server broker
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				processIPv4(ipv4)
			} else if ipv6 := ip.To16(); ipv6 != nil {
				processIPv6(ipv6)
			}
		}
	}
	cache.ServerAddrCache.Store(server.Name, addresses)
}

// GetServerAddrs - retrieves the addresses of given server
func GetServerAddrs(serverName string) []net.IPNet {
	addrs := []net.IPNet{}
	if val, ok := cache.ServerAddrCache.Load(serverName); ok {
		if valAddrs, ok := val.([]net.IPNet); ok {
			addrs = valAddrs
		}
	}
	return addrs
}

func processIPv4(ipv4 net.IP) {
	if _, ok := foundIPSet[ipv4.String()]; !ok {
		_, cidr6, err := net.ParseCIDR(fmt.Sprintf("%s/32", ipv4.String()))
		if err == nil {
			addresses = append(addresses, *cidr6)
		}
		foundIPSet[ipv4.String()] = struct{}{}
	}
}

func processIPv6(ipv6 net.IP) {
	if _, ok := foundIPSet[ipv6.String()]; !ok {
		_, cidr6, err := net.ParseCIDR(fmt.Sprintf("%s/128", ipv6.String()))
		if err == nil {
			addresses = append(addresses, *cidr6)
		}
		foundIPSet[ipv6.String()] = struct{}{}
	}
}
