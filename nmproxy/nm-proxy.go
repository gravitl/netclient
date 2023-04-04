package nmproxy

import (
	"context"
	"fmt"
	"sync"

	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/manager"
	ncmodels "github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/nmproxy/server"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// Start - setups the global cfg for proxy and starts the proxy server
func Start(ctx context.Context, wg *sync.WaitGroup, mgmChan chan *models.HostPeerUpdate, hostNatInfo *ncmodels.HostInfo, proxyPort int) {

	if config.GetCfg().IsProxyRunning() {
		logger.Log(1, "Proxy is running already...")
		return
	}
	logger.Log(0, "Starting Proxy...")
	defer wg.Done()

	if proxyPort == 0 {
		proxyPort = models.NmProxyPort
	}
	config.InitializeCfg()
	defer config.Reset()
	if hostNatInfo != nil {
		logger.Log(0, fmt.Sprintf("set nat info: %v", hostNatInfo))
		config.GetCfg().SetHostInfo(*hostNatInfo)
	}
	if config.GetCfg().HostInfo.PrivIp == nil || config.GetCfg().HostInfo.PublicIp == nil {
		logger.FatalLog("failed to create proxy, check if stun list is configured correctly on your server")
	}
	// start the netclient proxy server
	err := server.NmProxyServer.CreateProxyServer(proxyPort, 0, config.GetCfg().GetHostInfo().PrivIp.String())
	if err != nil {
		logger.FatalLog("failed to create proxy: ", err.Error())
	}
	config.GetCfg().SetServerConn(server.NmProxyServer.Server)
	go manager.Start(ctx, mgmChan)
	server.NmProxyServer.Listen(ctx)
}
