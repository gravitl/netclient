package functions

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/local"
	"github.com/gravitl/netclient/mq"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/networking"
	"github.com/gravitl/netclient/nmproxy"
	proxyCfg "github.com/gravitl/netclient/nmproxy/config"
	ncmodels "github.com/gravitl/netclient/nmproxy/models"
	"github.com/gravitl/netclient/nmproxy/stun"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	// CheckInInterval - interval in minutes for mq checkins
	CheckInInterval = 1
)

var (
	ProxyManagerChan = make(chan *models.HostPeerUpdate, 50)
	hostNatInfo      *ncmodels.HostInfo
)

func startProxy(wg *sync.WaitGroup) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	wg.Add(1)
	go nmproxy.Start(ctx, wg, ProxyManagerChan, hostNatInfo, config.Netclient().ProxyListenPort)
	return cancel
}

// Daemon runs netclient daemon
func Daemon() {
	logger.Log(0, "netclient daemon started -- version:", config.Version)
	if err := ncutils.SavePID(); err != nil {
		logger.FatalLog("unable to save PID on daemon startup")
	}
	if err := local.SetIPForwarding(); err != nil {
		logger.Log(0, "unable to set IPForwarding", err.Error())
	}
	wg := sync.WaitGroup{}
	quit := make(chan os.Signal, 1)
	reset := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, os.Interrupt)
	signal.Notify(reset, syscall.SIGHUP)
	shouldUpdateNat := getNatInfo()
	if shouldUpdateNat { // will be reported on check-in
		if err := config.WriteNetclientConfig(); err == nil {
			logger.Log(1, "updated NAT type to", hostNatInfo.NatType)
		}
	}
	cancel := startGoRoutines(&wg)
	stopProxy := startProxy(&wg)

	for {
		select {
		case <-quit:
			logger.Log(0, "shutting down netclient daemon")
			closeRoutines([]context.CancelFunc{
				cancel,
				stopProxy,
			}, &wg)
			logger.Log(0, "shutdown complete")
			return
		case <-reset:
			logger.Log(0, "received reset")
			closeRoutines([]context.CancelFunc{
				cancel,
				stopProxy,
			}, &wg)
			logger.Log(0, "restarting daemon")
			shouldUpdateNat := getNatInfo()
			if shouldUpdateNat { // will be reported on check-in
				if err := config.WriteNetclientConfig(); err == nil {
					logger.Log(1, "updated NAT type to", hostNatInfo.NatType)
				}
			}
			cancel = startGoRoutines(&wg)
			if !proxyCfg.GetCfg().ProxyStatus {
				stopProxy = startProxy(&wg)
			}
		}
	}
}

func closeRoutines(closers []context.CancelFunc, wg *sync.WaitGroup) {
	for i := range closers {
		closers[i]()
	}
	for _, mqclient := range mq.ServerSet {
		if mqclient != nil {
			mqclient.Disconnect(250)
		}
	}
	wg.Wait()
	logger.Log(0, "closing netmaker interface")
	iface := wireguard.GetInterface()
	iface.Close()
}

// startGoRoutines starts the daemon goroutines
func startGoRoutines(wg *sync.WaitGroup) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := config.ReadNetclientConfig(); err != nil {
		logger.Log(0, "error reading neclient config file", err.Error())
	}
	config.UpdateNetclient(*config.Netclient())
	if err := config.ReadNodeConfig(); err != nil {
		logger.Log(0, "error reading node map from disk", err.Error())
	}
	if err := config.ReadServerConf(); err != nil {
		logger.Log(0, "errors reading server map from disk", err.Error())
	}
	logger.Log(3, "configuring netmaker wireguard interface")
	nc := wireguard.NewNCIface(config.Netclient(), config.GetNodes())
	nc.Create()
	nc.Configure()
	wireguard.SetPeers()
	if len(config.Servers) == 0 {
		ProxyManagerChan <- &models.HostPeerUpdate{
			ProxyUpdate: models.ProxyManagerPayload{
				Action: models.ProxyDeleteAllPeers,
			},
		}
	}
	for _, server := range config.Servers {
		logger.Log(1, "started daemon for server ", server.Name)
		server := server
		wg.Add(1)
		go mq.MessageQueue(ctx, wg, &server)
	}
	wg.Add(1)
	go Checkin(ctx, wg)
	wg.Add(1)
	go networking.StartIfaceDetection(ctx, wg, config.Netclient().ProxyListenPort)
	return cancel
}

// UpdateKeys -- updates private key and returns new publickey
func UpdateKeys(node *config.Node, host *config.Config, client mqtt.Client) error {
	var err error
	logger.Log(0, "received message to update wireguard keys for network ", node.Network)
	host.PrivateKey, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		logger.Log(0, "network:", node.Network, "error generating privatekey ", err.Error())
		return err
	}
	file := config.GetNetclientPath() + "netmaker.conf"
	if err := wireguard.UpdatePrivateKey(file, host.PrivateKey.String()); err != nil {
		logger.Log(0, "network:", node.Network, "error updating wireguard key ", err.Error())
		return err
	}
	host.PublicKey = host.PrivateKey.PublicKey()
	if err := config.WriteNetclientConfig(); err != nil {
		logger.Log(0, "error saving netclient config", err.Error())
	}
	mq.PublishNodeUpdate(node)
	return nil
}

// RemoveServer - removes a server from server conf given a specific node
func RemoveServer(node *config.Node) {
	logger.Log(0, "removing server", node.Server, "from mq")
	delete(mq.ServerSet, node.Server)
}

func getNatInfo() (natUpdated bool) {
	ncConf, err := config.ReadNetclientConfig()
	if err != nil {
		logger.Log(0, "errors reading netclient from disk", err.Error())
		return
	}
	err = config.ReadServerConf()
	if err != nil {
		logger.Log(0, "errors reading server map from disk", err.Error())
		return
	}

	for _, server := range config.Servers {
		server := server
		if hostNatInfo == nil {
			portToStun, err := ncutils.GetFreePort(config.Netclient().ProxyListenPort)
			if portToStun == 0 || err != nil {
				portToStun = config.Netclient().ListenPort
			}

			hostNatInfo = stun.GetHostNatInfo(
				server.StunList,
				config.Netclient().EndpointIP.String(),
				portToStun,
			)
			if len(ncConf.Host.NatType) == 0 || ncConf.Host.NatType != hostNatInfo.NatType {
				config.Netclient().Host.NatType = hostNatInfo.NatType
				return true
			}
		}
	}
	return
}

// Checkin  -- go routine that checks for public or local ip changes, publishes changes
//
//	if there are no updates, simply "pings" the server as a checkin
func Checkin(ctx context.Context, wg *sync.WaitGroup) {
	logger.Log(2, "starting checkin goroutine")
	defer wg.Done()
	ticker := time.NewTicker(time.Minute * CheckInInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Log(0, "checkin routine closed")
			return
		case <-ticker.C:
			for server, mqclient := range mq.ServerSet {
				mqclient := mqclient
				if mqclient == nil || !mqclient.IsConnected() {
					logger.Log(0, "MQ client is not connected, skipping checkin for server", server)
					continue
				}
			}
			if len(config.GetServers()) > 0 {
				checkin()
			}

		}
	}
}

func checkin() {

	if err := UpdateHostSettings(); err != nil {
		logger.Log(0, "failed to update host settings -", err.Error())
		return
	}

	if err := mq.PublishGlobalHostUpdate(models.HostMqAction(models.CheckIn)); err != nil {
		logger.Log(0, "failed to check-in", err.Error())
	}

}

// UpdateHostSettings - checks local host settings, if different, mod config and publish
func UpdateHostSettings() error {
	_ = config.ReadNodeConfig()
	_ = config.ReadServerConf()
	logger.Log(3, "checkin with server(s)")
	var (
		publicIP   string
		err        error
		publishMsg bool
	)
	for _, node := range config.GetNodes() {
		node := node
		server := config.GetServer(node.Server)
		if node.Connected && len(publicIP) == 0 { // only run this until IP is found
			if !config.Netclient().IsStatic {
				publicIP, err = ncutils.GetPublicIP(server.API)
				if err != nil {
					logger.Log(1, "error encountered checking public ip addresses: ", err.Error())
				}
				if len(publicIP) > 0 && config.Netclient().EndpointIP.String() != publicIP {
					logger.Log(0, "endpoint has changed from", config.Netclient().EndpointIP.String(), "to", publicIP)
					config.Netclient().EndpointIP = net.ParseIP(publicIP)
					publishMsg = true
				}
			}
		}
		if server.Is_EE && node.Connected {
			logger.Log(0, "collecting metrics for network", node.Network)
			mq.PublishMetrics(&node)
		}
	}

	ifacename := ncutils.GetInterfaceName()
	var proxylistenPort int
	var proxypublicport int
	if config.Netclient().ProxyEnabled {
		proxylistenPort = proxyCfg.GetCfg().HostInfo.PrivPort
		proxypublicport = proxyCfg.GetCfg().HostInfo.PubPort
		if proxylistenPort == 0 {
			proxylistenPort = models.NmProxyPort
		}
		if proxypublicport == 0 {
			proxypublicport = models.NmProxyPort
		}
	}
	localPort, err := GetLocalListenPort(ifacename)
	if err != nil {
		logger.Log(1, "error encountered checking local listen port: ", ifacename, err.Error())
	} else if config.Netclient().ListenPort != localPort && localPort != 0 {
		logger.Log(1, "local port has changed from ", strconv.Itoa(config.Netclient().ListenPort), " to ", strconv.Itoa(localPort))
		config.Netclient().ListenPort = localPort
		publishMsg = true
	}
	if config.Netclient().ProxyEnabled {

		if config.Netclient().ProxyListenPort != proxylistenPort {
			logger.Log(1, fmt.Sprint("proxy listen port has changed from ", config.Netclient().ProxyListenPort, " to ", proxylistenPort))
			config.Netclient().ProxyListenPort = proxylistenPort
			publishMsg = true
		}
		if config.Netclient().PublicListenPort != proxypublicport {
			logger.Log(1, fmt.Sprint("public listen port has changed from ", config.Netclient().PublicListenPort, " to ", proxypublicport))
			config.Netclient().PublicListenPort = proxypublicport
			publishMsg = true
		}
	}
	if !config.Netclient().ProxyEnabledSet && proxyCfg.GetCfg().ShouldUseProxy() &&
		!config.Netclient().ProxyEnabled && !proxyCfg.NatAutoSwitchDone() {
		logger.Log(0, "Host is behind NAT, enabling proxy...")
		proxyCfg.SetNatAutoSwitch()
		config.Netclient().ProxyEnabled = true
		publishMsg = true
	}
	ip, err := getInterfaces()
	if err != nil {
		logger.Log(0, "failed to retrieve local interfaces during check-in", err.Error())
	} else {
		if ip != nil {
			if len(*ip) != len(config.Netclient().Interfaces) {
				config.Netclient().Interfaces = *ip
				publishMsg = true
			}
		}
	}
	defaultInterface, err := getDefaultInterface()
	if err != nil {
		logger.Log(0, "default gateway not found", err.Error())
	} else {
		if defaultInterface != config.Netclient().DefaultInterface {
			publishMsg = true
			config.Netclient().DefaultInterface = defaultInterface
		}
	}
	if publishMsg {
		if err := config.WriteNetclientConfig(); err != nil {
			return err
		}
		logger.Log(0, "publishing global host update for port changes")
		if err := mq.PublishGlobalHostUpdate(models.UpdateHost); err != nil {
			logger.Log(0, "could not publish local port change", err.Error())
		}
	}

	return err
}
