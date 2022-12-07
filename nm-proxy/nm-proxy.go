package nmproxy

import (
	"context"
	"fmt"
	"net"

	"github.com/gravitl/netclient/nm-proxy/config"
	"github.com/gravitl/netclient/nm-proxy/manager"
	"github.com/gravitl/netclient/nm-proxy/server"
	"github.com/gravitl/netclient/nm-proxy/stun"
	"github.com/gravitl/netmaker/logger"
)

func Start(ctx context.Context, mgmChan chan *manager.ProxyManagerPayload, stunAddr, stunPort string, fromServer bool) {

	if config.GetGlobalCfg().IsProxyRunning() {
		logger.Log(1, "Proxy is running already...")
		return
	}
	logger.Log(1, "Starting Proxy...")
	if stunAddr == "" || stunPort == "" {
		logger.Log(1, "stun config values cannot be empty")
		return
	}
	config.InitializeGlobalCfg()
	config.GetGlobalCfg().SetIsHostNetwork(!fromServer)
	hInfo := stun.GetHostInfo(stunAddr, stunPort)
	stun.Host = hInfo
	logger.Log(0, fmt.Sprintf("HOSTINFO: %+v", hInfo))
	if hInfo.PrivIp != nil && IsPublicIP(hInfo.PrivIp) {
		logger.Log(1, "Host is public facing!!!")
	}
	// start the netclient proxy server
	err := server.NmProxyServer.CreateProxyServer(hInfo.PrivPort, 0, hInfo.PrivIp.String())
	if err != nil {
		logger.FatalLog("failed to create proxy: ", err.Error())
	}
	go manager.StartProxyManager(ctx, mgmChan)
	server.NmProxyServer.Listen(ctx)

}

// IsPublicIP indicates whether IP is public or not.
func IsPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return false
	}
	return true
}
