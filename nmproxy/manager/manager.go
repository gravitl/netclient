package manager

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/nmproxy/config"
	"github.com/gravitl/netclient/nmproxy/models"
	peerpkg "github.com/gravitl/netclient/nmproxy/peer"
	"github.com/gravitl/netclient/nmproxy/turn"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	nm_models "github.com/gravitl/netmaker/models"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type proxyPayload nm_models.ProxyManagerPayload

func getRecieverType(m *nm_models.ProxyManagerPayload) *proxyPayload {
	mI := proxyPayload(*m)
	return &mI
}

func dumpProxyConnsInfo(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-config.DumpSignalChan:
			config.GetCfg().Dump()
		}
	}
}

// Start - starts the proxy manager loop and listens for events on the Channel provided
func Start(ctx context.Context, wg *sync.WaitGroup, managerChan chan *nm_models.HostPeerUpdate) {
	defer wg.Done()
	wg.Add(1)
	go dumpProxyConnsInfo(ctx, wg)
	for {
		select {
		case <-ctx.Done():
			logger.Log(0, "shutting down proxy manager...")
			return
		case mI := <-managerChan:
			if mI == nil {
				continue
			}
			logger.Log(3, fmt.Sprintf("-------> PROXY-MANAGER: %+v\n", mI.ProxyUpdate))
			err := configureProxy(mI)
			if err != nil {
				logger.Log(1, "failed to configure proxy:  ", err.Error())
			}
		}
	}
}

// configureProxy - confgures proxy by payload action
func configureProxy(payload *nm_models.HostPeerUpdate) error {
	var err error
	m := getRecieverType(&payload.ProxyUpdate)
	m.InterfaceName = ncutils.GetInterfaceName()
	m.Peers = payload.Peers

	config.GetCfg().SetPeersIDsAndAddrs(m.Server, payload.HostPeerIDs)
	startMetricsThread(payload) // starts or stops the metrics collection based on host proxy setting

	switch m.Action {
	case nm_models.ProxyUpdate, nm_models.NoProxy:
		m.peerUpdate()
	case nm_models.ProxyDeleteAllPeers:
		cleanUpInterface()

	}
	return err
}

func startMetricsThread(peerUpdate *nm_models.HostPeerUpdate) {
	if !config.GetCfg().GetMetricsCollectionStatus() {
		ctx, cancel := context.WithCancel(context.Background())
		go peerpkg.StartMetricsCollectionForHostPeers(ctx)
		config.GetCfg().SetMetricsThreadCtx(cancel)
	}
}

func cleanUpInterface() {
	logger.Log(1, "cleaning up proxy peer connections")
	peerConnMap := config.GetCfg().GetAllProxyPeers()
	for _, peerI := range peerConnMap {
		config.GetCfg().RemovePeer(peerI.Key.String())
		wireguard.UpdatePeer(&peerI.Config.PeerConf)
	}

}

// ProxyManagerPayload.peerUpdate - processes the peer update
func (m *proxyPayload) peerUpdate() error {

	for _, peerI := range m.Peers {

		peerConf := m.PeerMap[peerI.PublicKey.String()]
		if peerI.Endpoint == nil {
			logger.Log(1, "Endpoint nil for peer: ", peerI.PublicKey.String())
			continue
		}

		var isRelayed bool
		var relayedTo *net.UDPAddr
		if m.IsRelayed {
			isRelayed = true
			relayedTo = m.RelayedTo
		} else {

			isRelayed = peerConf.IsRelayed
			relayedTo = peerConf.RelayedTo

		}
		if peerI.Remove {
			// peer has been deleted so skip
			continue
		}
		var shouldUseProxy bool
		if isRelayed {
			shouldUseProxy = true
		}
		if peerConf.Proxy && m.Action == nm_models.ProxyUpdate {
			shouldUseProxy = true
		}
		if !isRelayed && turn.ShouldUseTurn(config.GetCfg().HostInfo.NatType) && turn.ShouldUseTurn(peerConf.NatType) {
			if t := config.GetCfg().GetTurnCfg(); t != nil {
				go func(serverName string, peer wgtypes.PeerConfig, peerConf nm_models.PeerConf, t *models.TurnCfg) {
					var err error
					// signal peer with the host relay addr for the peer
					peerTurnCfg, ok := config.GetCfg().GetPeerTurnCfg(peer.PublicKey.String())
					if !ok {
						config.GetCfg().SetPeerTurnCfg(peer.PublicKey.String(), models.TurnPeerCfg{
							Server:   serverName,
							PeerConf: peerConf,
						})
					} else {
						peerTurnCfg.PeerConf = peerConf
						config.GetCfg().UpdatePeerTurnCfg(peer.PublicKey.String(), peerTurnCfg)
					}
					err = turn.SignalPeer(serverName, nm_models.Signal{
						Server:            m.Server,
						FromHostPubKey:    config.GetCfg().GetDevicePubKey().String(),
						TurnRelayEndpoint: t.TurnConn.LocalAddr().String(),
						ToHostPubKey:      peer.PublicKey.String(),
						Action:            nm_models.ConnNegotiation,
					})
					if err != nil {
						logger.Log(0, "---> failed to signal peer: ", err.Error())

					}

				}(m.Server, peerI, peerConf, t)
				continue
			}

		}
		if shouldUseProxy {
			peerpkg.AddNew(m.Server, peerI, peerConf, isRelayed, relayedTo, false)
		}

	}
	/* after processing peer update proxy connections
	are dumped to a file under netclient data path */
	config.DumpSignalChan <- struct{}{}
	return nil
}
