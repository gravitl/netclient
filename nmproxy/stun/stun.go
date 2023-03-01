package stun

import (
	"net"
	"strconv"
	"strings"

	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netmaker/logger"
	"gortc.io/stun"
)

const (
	SYMMETRIC_NAT  = "symnat"
	ASYMMETRIC_NAT = "asymnat"
	DOUBLE_NAT     = "doublenat"
)

// GetHostInfo - calls stun server for udp hole punch and fetches host info
func GetHostInfo(stunList string, proxyPort int) (info models.HostInfo) {

	// list of stun servers to traverse
	stunServers := strings.Split(stunList, ",")

	// need to store results from two different stun servers to determine nat type
	var ip1 net.IP
	var ip2 net.IP
	var port1 int
	var port2 int

	// traverse through stun servers, continue if any error is encountered
	for _, stunServer := range stunServers {
		s, err := net.ResolveUDPAddr("udp", stunServer)
		if err != nil {
			logger.Log(1, "failed to resolve udp addr: ", err.Error())
			continue
		}
		l := &net.UDPAddr{
			IP:   net.ParseIP(""),
			Port: proxyPort,
		}
		conn, err := net.DialUDP("udp", l, s)
		if err != nil {
			logger.Log(1, "failed to dial: ", err.Error())
			continue
		}
		defer conn.Close()
		c, err := stun.NewClient(conn)
		if err != nil {
			logger.Log(1, "failed to create stun client: ", err.Error())
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
		}); err != nil {
			logger.Log(1, "2:stun error: ", err.Error())
			continue
		}
		// if ip1 is unset, set it; else, if ip2 is unset, set it
		if ip1.String() == "" && info.PublicIp.String() != "" {
			ip1 = info.PublicIp
		} else if ip1.String() != "" && ip2.String() == "" && info.PublicIp.String() != "" {
			ip2 = info.PublicIp
		}

		// if port1 is unset, set it; else, if port2 is unset, set it
		if port1 == 0 && info.PubPort != 0 {
			port1 = info.PubPort
		} else if port1 != 0 && port2 == 0 && info.PubPort != 0 {
			port2 = info.PubPort
		}

		// if ip1, ip2, port1, and port2 are all set, get the nat type, and exit loop
		if ip1.String() != "" && ip2.String() == "" && port1 != 0 && port2 != 0 {
			info.NatType = getNatType(ip1.String(), ip2.String(), port1, port2, proxyPort)
			break
		}
	}
	return
}

// compare ports and endpoints between stun results to determine nat type
func getNatType(ip1, ip2 string, port1, port2, proxyPort int) string {
	natType := ""
	if ip1 == ip2 && port1 == port2 && port1 == proxyPort {
		natType = SYMMETRIC_NAT
	} else if ip1 == ip2 && port1 == port2 {
		natType = ASYMMETRIC_NAT
	} else if port1 != port2 {
		natType = DOUBLE_NAT
	}
	return natType
}
