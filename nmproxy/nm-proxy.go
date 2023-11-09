package nmproxy

import (
	"context"
	"sync"
	"time"

	ncconfig "github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/turn"
	"github.com/gravitl/netclient/nmproxy/wg"
	"github.com/gravitl/netmaker/logger"
)

// Start - setups the global cfg for proxy and starts the proxy server
func Start(ctx context.Context, waitg *sync.WaitGroup) {
	defer logger.Log(0, "Shutting Down Proxy...")
	defer waitg.Done()
	config.InitializeCfg()
	defer config.Reset()
	wgIface, err := wg.GetWgIface(ncutils.GetInterfaceName())
	if err != nil {
		logger.Log(1, "Failed get interface config: ", err.Error())
		return
	}
	config.GetCfg().SetIface(wgIface)
	proxyWaitG := &sync.WaitGroup{}
	proxyWaitG.Add(1)
	go turn.WatchPeerSignals(ctx, proxyWaitG)
	turnCfgs := ncconfig.GetAllTurnConfigs()
	if len(turnCfgs) > 0 {
		time.Sleep(time.Second * 2) // add a delay for clients to send turn register message to server
		turn.Init(ctx, proxyWaitG, turnCfgs)
		defer turn.DissolvePeerConnections()
		proxyWaitG.Add(1)
		go turn.WatchPeerConnections(ctx, proxyWaitG)
	}
	proxyWaitG.Wait()
}
