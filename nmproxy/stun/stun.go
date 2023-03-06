package stun

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netmaker/logger"
	nmmodels "github.com/gravitl/netmaker/models"
	"gortc.io/stun"
)

// GetHostInfo - calls stun server for udp hole punch and fetches host info
func GetHostInfo(stunList []nmmodels.StunServer, proxyPort int) (info models.HostInfo) {

	// need to store results from two different stun servers to determine nat type
	endpointList := []stun.XORMappedAddress{}

	info.NatType = config.DOUBLE_NAT

	// traverse through stun servers, continue if any error is encountered
	for _, stunServer := range stunList {
		s, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", stunServer.Domain, stunServer.Port))
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
			info.NatType = getNatType(endpointList[:], proxyPort)
			conn.Close()
			break
		}
		conn.Close()
	}
	return
}

// compare ports and endpoints between stun results to determine nat type
func getNatType(endpointList []stun.XORMappedAddress, proxyPort int) string {
	natType := config.DOUBLE_NAT
	ip1 := endpointList[0].IP
	ip2 := endpointList[1].IP
	port1 := endpointList[0].Port
	port2 := endpointList[1].Port
	if ip1.Equal(ip2) && port1 == port2 && port1 == proxyPort {
		natType = config.SYMMETRIC_NAT
	} else if ip1.Equal(ip2) && port1 == port2 && port1 != proxyPort {
		natType = config.ASYMMETRIC_NAT
	}
	return natType
}
