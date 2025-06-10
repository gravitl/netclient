package stun

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
	nmmodels "github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
	"gortc.io/stun"
)

var (
	StunServers = []StunServer{
		{Domain: "stun1.l.google.com", Port: 19302},
		{Domain: "stun2.l.google.com", Port: 19302},
		{Domain: "stun3.l.google.com", Port: 19302},
		{Domain: "stun4.l.google.com", Port: 19302},
	}
)

// StunServer - struct to hold data required for using stun server
type StunServer struct {
	Domain string `json:"domain" yaml:"domain"`
	Port   int    `json:"port" yaml:"port"`
}

// LoadStunServers - load customized stun servers
func LoadStunServers(list string) {
	l1 := strings.Split(list, ",")
	stunServers := []StunServer{}
	for _, v := range l1 {
		l2 := strings.Split(v, ":")
		if len(l2) < 2 {
			continue
		}
		port, _ := strconv.Atoi(l2[1])
		sS := StunServer{Domain: l2[0], Port: port}
		stunServers = append(stunServers, sS)
	}
	if len(stunServers) > 0 {
		StunServers = stunServers
	}

}

func SetDefaultStunServers() {
	StunServers = []StunServer{
		{Domain: "stun1.l.google.com", Port: 19302},
		{Domain: "stun2.l.google.com", Port: 19302},
		{Domain: "stun3.l.google.com", Port: 19302},
		{Domain: "stun4.l.google.com", Port: 19302},
	}
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
func HolePunch(portToStun, proto int) (publicIP net.IP, publicPort int, natType string) {
	server := config.GetServer(config.CurrServer)
	if server == nil {
		server = &config.Server{}
		server.Stun = true
		SetDefaultStunServers()
	}
	if !server.Stun {
		return
	}

	for _, stunServer := range StunServers {
		var err4 error
		var err6 error
		if proto == 4 {
			publicIP, publicPort, natType, err4 = callHolePunch(stunServer, portToStun, "udp4")
			if err4 != nil {
				slog.Warn("callHolePunch udp4 error", err4.Error())
			}
		} else {
			publicIP, publicPort, natType, err6 = callHolePunch(stunServer, portToStun, "udp6")
			if err6 != nil {
				slog.Warn("callHolePunch udp6 error", err6.Error())
			}
		}
		if err4 != nil || err6 != nil {
			continue
		}
		break
	}
	slog.Debug("hole punching complete", "public ip", publicIP.String(), "public port", strconv.Itoa(publicPort), "nat type", natType)
	return
}

func callHolePunch(stunServer StunServer, portToStun int, network string) (publicIP net.IP, publicPort int, natType string, err error) {
	s, err := net.ResolveUDPAddr(network, fmt.Sprintf("%s:%d", stunServer.Domain, stunServer.Port))
	if err != nil {
		logger.Log(1, "failed to resolve udp addr: ", network, err.Error())
		return nil, 0, "", err
	}
	l := &net.UDPAddr{
		IP:   net.ParseIP(""),
		Port: portToStun,
	}
	slog.Debug(fmt.Sprintf("hole punching port %d via stun server %s:%d", portToStun, stunServer.Domain, stunServer.Port))
	publicIP, publicPort, natType, err = doStunTransaction(l, s)
	if err != nil {
		logger.Log(3, "stun transaction failed: ", stunServer.Domain, err.Error())
		return nil, 0, natType, err
	}

	return
}

func doStunTransaction(lAddr, rAddr *net.UDPAddr) (publicIP net.IP, publicPort int, natType string, err error) {
	conn, err := net.DialUDP("udp", lAddr, rAddr)
	if err != nil {
		logger.Log(1, "failed to dial: ", err.Error())
		return
	}
	re := conn.LocalAddr().String()
	lIP := re[0:strings.LastIndex(re, ":")]
	if strings.ContainsAny(lIP, "[") {
		lIP = strings.ReplaceAll(lIP, "[", "")
	}
	if strings.ContainsAny(lIP, "]") {
		lIP = strings.ReplaceAll(lIP, "]", "")
	}

	privIp := net.ParseIP(lIP)
	defer func() {
		if publicIP != nil && privIp != nil && !privIp.Equal(publicIP) {
			natType = nmmodels.NAT_Types.BehindNAT
		} else {
			natType = nmmodels.NAT_Types.Public
		}
	}()
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
	var err1 error
	err = c.Do(message, func(res stun.Event) {
		if res.Error != nil {
			logger.Log(1, "0:stun error: ", res.Error.Error())
			err1 = res.Error
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
	})
	if err != nil {
		logger.Log(1, "2:stun error: ", err.Error())
	}
	if err1 != nil {
		logger.Log(3, "3:stun error: ", err1.Error())
		return nil, 0, natType, err1
	}
	return
}
