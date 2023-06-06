package nmproxy

import (
	"context"
	"sync"
	"time"

	ncconfig "github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/nmproxy/config"
	ncmodels "github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/nmproxy/turn"
	"github.com/gravitl/netmaker/models"
)

// Start - setups the global cfg for proxy and starts the proxy server
func Start(ctx context.Context, wg *sync.WaitGroup,
	mgmChan chan *models.HostPeerUpdate, hostNatInfo *ncmodels.HostInfo, proxyPort int) {

	defer wg.Done()

	config.InitializeCfg()
	defer config.Reset()
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
}
