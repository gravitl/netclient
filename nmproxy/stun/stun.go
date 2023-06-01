package stun

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netmaker/logger"
	nmmodels "github.com/gravitl/netmaker/models"
	"gortc.io/stun"
)

// IsPublicIP indicates whether IP is public or not.
func IsPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return false
	}
	return true
}

// DoesIPExistLocally - checks if the IP address exists on a local interface
func DoesIPExistLocally(ip net.IP) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for i := range ifaces {
		addrs, err := ifaces[i].Addrs()
		if err == nil {
			for j := range addrs {
				netIP, _, err := net.ParseCIDR(addrs[j].String())
				if err == nil {
					if netIP.Equal(ip) {
						return true
					}
				}
			}
		}
	}
	return false
}

// HolePunch - performs udp hole punching on the given port
func HolePunch(stunList []nmmodels.StunServer, portToStun int) (publicIP net.IP, publicPort int) {
	for _, stunServer := range stunList {
		stunServer := stunServer
		s, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", stunServer.Domain, stunServer.Port))
		if err != nil {
			logger.Log(1, "failed to resolve udp addr: ", err.Error())
			continue
		}
		l := &net.UDPAddr{
			IP:   net.ParseIP(""),
			Port: portToStun,
		}
		publicIP, publicPort, err = doStunTransaction(l, s)
		if err != nil {
			logger.Log(0, "stun transaction failed: ", stunServer.Domain, err.Error())
			continue
		}
		break
	}
	return
}

func doStunTransaction(lAddr, rAddr *net.UDPAddr) (publicIP net.IP, publicPort int, err error) {
	conn, err := net.DialUDP("udp", lAddr, rAddr)
	if err != nil {
		logger.Log(0, "failed to dial: ", err.Error())
		return
	}
	defer conn.Close()
	c, err := stun.NewClient(conn)
	if err != nil {
		logger.Log(1, "failed to create stun client: ", err.Error())
		return
	}
	defer c.Close()
	// Building binding request with random transaction id.
	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	// Sending request to STUN server, waiting for response message.
	if err := c.Do(message, func(res stun.Event) {
		if res.Error != nil {
			logger.Log(1, "0:stun error: ", res.Error.Error())
			return
		}
		// Decoding XOR-MAPPED-ADDRESS attribute from message.
		var xorAddr stun.XORMappedAddress
		if err := xorAddr.GetFrom(res.Message); err != nil {
			logger.Log(1, "1:stun error: ", res.Error.Error())
			return
		}
		publicIP = xorAddr.IP
		publicPort = xorAddr.Port
	}); err != nil {
		logger.Log(1, "2:stun error: ", err.Error())
	}
	return
}

// GetHostNatInfo - calls stun server for udp hole punch and fetches host info
func GetHostNatInfo(stunList []nmmodels.StunServer, currentPublicIP string, stunPort int) (info *models.HostInfo) {

	info = &models.HostInfo{
		PublicIp: net.ParseIP(currentPublicIP),
	}
	// need to store results from two different stun servers to determine nat type
	endpointList := []stun.XORMappedAddress{}
	info.NatType = nmmodels.NAT_Types.Double

	// traverse through stun servers, continue if any error is encountered
	for _, stunServer := range stunList {
		stunServer := stunServer
		s, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", stunServer.Domain, stunServer.Port))
		if err != nil {
			logger.Log(1, "failed to resolve udp addr: ", err.Error())
			continue
		}
		l := &net.UDPAddr{
			IP:   net.ParseIP(""),
			Port: stunPort,
		}
		conn, err := net.DialUDP("udp", l, s)
		if err != nil {
			logger.Log(0, "failed to dial: ", err.Error())
			continue
		}
		defer conn.Close()
		c, err := stun.NewClient(conn)
		if err != nil {
			logger.Log(1, "failed to create stun client: ", err.Error())
			conn.Close()
			continue
		}
		defer c.Close()
		re := strings.Split(conn.LocalAddr().String(), ":")
		info.PrivIp = net.ParseIP(re[0])
		info.PrivPort, _ = strconv.Atoi(re[1])
		// Building binding request with random transaction id.
		message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		// Sending request to STUN server, waiting for response message.
		if err := c.Do(message, func(res stun.Event) {
			if res.Error != nil {
				logger.Log(1, "0:stun error: ", res.Error.Error())
				return
			}
			// Decoding XOR-MAPPED-ADDRESS attribute from message.
			var xorAddr stun.XORMappedAddress
			if err := xorAddr.GetFrom(res.Message); err != nil {
				logger.Log(1, "1:stun error: ", res.Error.Error())
				return
			}
			info.PublicIp = xorAddr.IP
			info.PubPort = xorAddr.Port
			endpointList = append(endpointList, xorAddr)
		}); err != nil {
			logger.Log(1, "2:stun error: ", err.Error())
			conn.Close()
			continue
		}
		if len(endpointList) > 1 {
			info.NatType = getNatType(endpointList[:], currentPublicIP, stunPort)
			conn.Close()
			break
		}
		conn.Close()
	}
	return
}

// compare ports and endpoints between stun results to determine nat type
func getNatType(endpointList []stun.XORMappedAddress, currentPublicIP string, stunPort int) string {
	natType := nmmodels.NAT_Types.Double
	ip1 := endpointList[0].IP
	ip2 := endpointList[1].IP
	port1 := endpointList[0].Port
	port2 := endpointList[1].Port
	if ip1.Equal(ip2) && IsPublicIP(ip1) && DoesIPExistLocally(ip1) {
		natType = nmmodels.NAT_Types.Public
	} else if ip1.Equal(ip2) && port1 == port2 && port1 == stunPort {
		natType = nmmodels.NAT_Types.Symmetric
	} else if ip1.Equal(ip2) && port1 == port2 && port1 != stunPort {
		natType = nmmodels.NAT_Types.Asymmetric
	}
	return natType
}
