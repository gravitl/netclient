package stun

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
	nmmodels "github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
	"gortc.io/stun"
)

const (
	// stunRTO is the per-attempt wait when UDP STUN is unreachable.
	// Paired with WithNoRetransmit so each server costs ~stunRTO, not ~8s.
	stunRTO = 500 * time.Millisecond
	// stunUnavailableBackoff skips further STUN attempts after a timeout,
	// avoiding long restart / IP-check loops in UDP-blocked environments.
	stunUnavailableBackoff = 5 * time.Minute
)

var (
	StunServers = []StunServer{
		{Domain: "stun1.l.google.com", Port: 19302},
		{Domain: "stun2.l.google.com", Port: 19302},
		{Domain: "stun3.l.google.com", Port: 19302},
		{Domain: "stun4.l.google.com", Port: 19302},
	}

	stunMu               sync.Mutex
	stunUnavailableUntil time.Time
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

func stunIsUnavailable() bool {
	stunMu.Lock()
	defer stunMu.Unlock()
	return time.Now().Before(stunUnavailableUntil)
}

func markStunUnavailable() {
	stunMu.Lock()
	defer stunMu.Unlock()
	stunUnavailableUntil = time.Now().Add(stunUnavailableBackoff)
	slog.Warn("udp stun appears blocked; skipping further stun attempts",
		"backoff", stunUnavailableBackoff.String())
}

func markStunAvailable() {
	stunMu.Lock()
	defer stunMu.Unlock()
	stunUnavailableUntil = time.Time{}
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
	if stunIsUnavailable() {
		slog.Debug("skipping hole punch; stun marked unavailable after recent timeout")
		return
	}

	network := "udp4"
	if proto != 4 {
		network = "udp6"
	}

	for _, stunServer := range StunServers {
		var err error
		publicIP, publicPort, natType, err = callHolePunch(stunServer, portToStun, network)
		if err != nil {
			slog.Warn("callHolePunch error", "network", network, "server", stunServer.Domain, "error", err.Error())
			// UDP blocked / no reply: other STUN servers will fail the same way.
			if errors.Is(err, stun.ErrTransactionTimeOut) {
				markStunUnavailable()
				break
			}
			continue
		}
		markStunAvailable()
		break
	}
	slog.Debug("hole punching complete", "public ip", publicIP.String(), "public port", strconv.Itoa(publicPort), "nat type", natType)
	return
}

func callHolePunch(stunServer StunServer, portToStun int, network string) (publicIP net.IP, publicPort int, natType string, err error) {
	s, err := net.ResolveUDPAddr(network, net.JoinHostPort(stunServer.Domain, fmt.Sprintf("%d", stunServer.Port)))
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
	// Short single-shot timeout: blocked UDP should fail in ~stunRTO, not ~8s.
	c, err := stun.NewClient(conn, stun.WithRTO(stunRTO), stun.WithNoRetransmit)
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
			logger.Log(1, "1:stun error: ", err.Error())
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
