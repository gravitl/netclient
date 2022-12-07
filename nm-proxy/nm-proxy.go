package nmproxy

import (
	"context"
	"fmt"

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
	config.GetGlobalCfg().SetHostInfo(stun.GetHostInfo(stunAddr, stunPort))
	logger.Log(0, fmt.Sprintf("HOSTINFO: %+v", config.GetGlobalCfg().GetHostInfo()))
	config.GetGlobalCfg().SetNATStatus()
	// start the netclient proxy server
	err := server.NmProxyServer.CreateProxyServer(config.GetGlobalCfg().GetHostInfo().PrivPort, 0, config.GetGlobalCfg().GetHostInfo().PrivIp.String())
	if err != nil {
		logger.FatalLog("failed to create proxy: ", err.Error())
	}
	go manager.StartProxyManager(ctx, mgmChan)
	server.NmProxyServer.Listen(ctx)

}
