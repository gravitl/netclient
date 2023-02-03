package stun

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netmaker/logger"
	"gortc.io/stun"
)

// GetHostInfo - calls stun server for udp hole punch and fetches host info
func GetHostInfo(stunHostAddr string, stunPort, proxyPort int) (info models.HostInfo) {

	s, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", stunHostAddr, stunPort))
	if err != nil {
		logger.Log(1, "failed to resolve udp addr: ", err.Error())
		return
	}
	l := &net.UDPAddr{
		IP:   net.ParseIP(""),
		Port: proxyPort,
	}
	conn, err := net.DialUDP("udp", l, s)
	if err != nil {
		logger.Log(1, "failed to dial: ", err.Error())
		return
	}
	defer conn.Close()
	c, err := stun.NewClient(conn)
	if err != nil {
		logger.Log(1, "failed to create stun client: ", err.Error())
		return
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
	}
	return
}
