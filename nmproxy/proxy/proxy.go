package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"

	"github.com/gravitl/netclient/nmproxy/common"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netmaker/logger"
)

// Proxy -  struct for wg proxy
type Proxy struct {
	Ctx        context.Context
	Cancel     context.CancelFunc
	Config     models.Proxy
	RemoteConn *net.UDPAddr
	LocalConn  net.Conn
}

// Proxy.Start - starts proxying the peer
func (p *Proxy) Start() error {

	var err error
	p.RemoteConn = p.Config.PeerEndpoint
	logger.Log(0, "----> Established Remote Conn with RPeer: %s, ----> RAddr: %s", p.Config.RemoteKey.String(), p.RemoteConn.String())
	addr, err := GetFreeIp(models.DefaultCIDR, config.GetCfg().GetInterfaceListenPort())
	if err != nil {
		logger.Log(1, "Failed to get freeIp: ", err.Error())
		return err
	}
	wgListenAddr, err := GetInterfaceListenAddr(config.GetCfg().GetInterfaceListenPort())
	if err != nil {
		logger.Log(1, "failed to get wg listen addr: ", err.Error())
		return err
	}
	if runtime.GOOS == "darwin" { // on darwin need listen on alias ip that was added to lo0
		wgListenAddr.IP = net.ParseIP(addr)
	}
	p.LocalConn, err = net.DialUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP(addr),
		Port: models.NmProxyPort,
	}, wgListenAddr)
	if err != nil {
		logger.Log(0, "failed dialing to local Wireguard port,Err: %v\n", err.Error())
		return err
	}

	logger.Log(0, "Dialing to local Wireguard port %s --> %s\n", p.LocalConn.LocalAddr().String(), p.LocalConn.RemoteAddr().String())
	err = p.updateEndpoint()
	if err != nil {
		logger.Log(0, "error while updating Wireguard peer endpoint [%s] %v\n", p.Config.RemoteKey.String(), err.Error())
		return err
	}
	localAddr, err := net.ResolveUDPAddr("udp", p.LocalConn.LocalAddr().String())
	if err != nil {
		logger.Log(0, "failed to resolve local addr: ", err.Error())
		return err
	}
	p.Config.LocalConnAddr = localAddr
	p.Config.RemoteConnAddr = p.RemoteConn
	go p.ProxyPeer()

	return nil
}

// Proxy.Close - removes peer conn from proxy and closes all the opened connections locally
func (p *Proxy) Close() {
	logger.Log(0, "------> Closing Proxy for ", p.Config.RemoteKey.String())
	p.Cancel()
	p.LocalConn.Close()
	if runtime.GOOS == "darwin" { // on darwin need to add alias for additional address in lo0 range
		host, _, err := net.SplitHostPort(p.LocalConn.LocalAddr().String())
		if err != nil {
			logger.Log(0, "Failed to split host: ", err.Error())
			return
		}

		if host != "127.0.0.1" {
			_, err = common.RunCmd(fmt.Sprintf("ifconfig lo0 -alias %s 255.255.255.255", host), true)
			if err != nil {
				logger.Log(0, "Failed to add alias: ", err.Error())
			}
		}

	}
}

// GetInterfaceListenAddr - gets interface listen addr
func GetInterfaceListenAddr(port int) (*net.UDPAddr, error) {
	locallistenAddr := "127.0.0.1"
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", locallistenAddr, port))
	if err != nil {
		return udpAddr, err
	}
	if !config.GetCfg().IsHostNetwork() {
		addrs, err := getBroadCastAddress()
		if err != nil {
			return udpAddr, err
		}
		for _, addr := range addrs {
			if liAddr := addr.(*net.IPNet).IP; liAddr != nil {
				udpAddr.IP = liAddr
				break
			}
		}
	}

	return udpAddr, nil
}

// getBoardCastAddress - gets the broadcast address
func getBroadCastAddress() ([]net.Addr, error) {
	localnets, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var (
		ief   net.Interface
		addrs []net.Addr
	)
	for _, ief = range localnets {
		if ief.Flags&net.FlagBroadcast != 0 && ief.Flags&net.FlagUp != 0 {
			addrs, err = ief.Addrs()
			if err == nil {
				return addrs, nil
			}

		}
	}
	return nil, errors.New("couldn't obtain the broadcast addr")
}
