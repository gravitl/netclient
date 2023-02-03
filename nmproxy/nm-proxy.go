package nmproxy

import (
	"context"
	"fmt"
	"sync"

	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/manager"
	"github.com/gravitl/netclient/nmproxy/server"
	"github.com/gravitl/netclient/nmproxy/stun"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// Start - setups the global cfg for proxy and starts the proxy server
func Start(ctx context.Context, wg *sync.WaitGroup, mgmChan chan *models.HostPeerUpdate, stunAddr string, stunPort, proxyPort int) {

	if config.GetCfg().IsProxyRunning() {
		logger.Log(1, "Proxy is running already...")
		return
	}
	logger.Log(0, "Starting Proxy...")
	defer wg.Done()
	if stunAddr == "" || stunPort == 0 {
		logger.Log(1, "stun config values cannot be empty")
		return
	}
	if proxyPort == 0 {
		proxyPort = models.NmProxyPort
	}
	config.InitializeCfg()
	defer config.Reset()
	config.GetCfg().SetHostInfo(stun.GetHostInfo(stunAddr, stunPort, proxyPort))
	logger.Log(0, fmt.Sprintf("HOSTINFO: %+v", config.GetCfg().GetHostInfo()))
	config.GetCfg().SetNATStatus()
	// start the netclient proxy server
	err := server.NmProxyServer.CreateProxyServer(proxyPort, 0, config.GetCfg().GetHostInfo().PrivIp.String())
	if err != nil {
		logger.FatalLog("failed to create proxy: ", err.Error())
	}
	config.GetCfg().SetServerConn(server.NmProxyServer.Server)
	go manager.Start(ctx, mgmChan)
	server.NmProxyServer.Listen(ctx)
}
