package proxy

import (
	"context"
	"fmt"
	"net"

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
	logger.Log(0, fmt.Sprintf("----> Established Remote Conn with RPeer: %s, ----> RAddr: %s", p.Config.PeerPublicKey.String(), p.RemoteConn.String()))
	p.LocalConn, err = net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", config.GetCfg().GetInterfaceListenPort()))
	if err != nil {
		logger.Log(0, "failed dialing to local Wireguard port,Err: %v\n", err.Error())
		return err
	}

	logger.Log(1, fmt.Sprintf("Dialing to local Wireguard port %s --> %s\n", p.LocalConn.LocalAddr().String(), p.LocalConn.RemoteAddr().String()))
	err = p.updateEndpoint()
	if err != nil {
		logger.Log(0, "error while updating Wireguard peer endpoint [%s] %v\n", p.Config.PeerPublicKey.String(), err.Error())
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
	logger.Log(0, "------> Closing Proxy for ", p.Config.PeerPublicKey.String())
	p.Cancel()
	p.LocalConn.Close()
}
