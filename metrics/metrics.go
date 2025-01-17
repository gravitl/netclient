package metrics

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/exp/slog"
	//lint:ignore SA1019 Reason: will be switching to a alternative package
	"github.com/go-ping/ping"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	tcp_ping "github.com/gravitl/tcping/ping"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// Collect - collects metrics
func Collect(network string, peerMap models.PeerMap, metricPort int) (*models.Metrics, error) {
	mi := 15
	server := config.GetServer(config.CurrServer)
	if server != nil {
		i, err := strconv.Atoi(server.MetricInterval)
		if err == nil && i > 0 {
			mi = i
		}
	}
	var metrics models.Metrics
	metrics.Connectivity = make(map[string]models.Metric)
	var wgclient, err = wgctrl.New()
	if err != nil {
		fillUnconnectedData(&metrics, peerMap, mi)
		return &metrics, err
	}
	defer wgclient.Close()
	device, err := wgclient.Device(ncutils.GetInterfaceName())
	if err != nil {
		fillUnconnectedData(&metrics, peerMap, mi)
		return &metrics, err
	}
	// TODO handle freebsd??
	for i := range device.Peers {
		currPeer := device.Peers[i]
		if _, ok := peerMap[currPeer.PublicKey.String()]; !ok {
			continue
		}
		id := peerMap[currPeer.PublicKey.String()].ID
		address := peerMap[currPeer.PublicKey.String()].Address
		isExtClient := peerMap[currPeer.PublicKey.String()].IsExtClient
		if id == "" || address == "" {
			logger.Log(0, "attempted to parse metrics for invalid peer from server", id, address)
			continue
		}

		var newMetric = models.Metric{
			NodeName: peerMap[currPeer.PublicKey.String()].Name,
		}
		slog.Debug("collecting metrics for peer", "address", address)
		newMetric.TotalReceived = currPeer.ReceiveBytes
		newMetric.TotalSent = currPeer.TransmitBytes
		if isExtClient {
			newMetric.Connected, newMetric.Latency = extPeerConnStatus(address)
		} else {
			newMetric.Connected, newMetric.Latency = PeerConnStatus(address, metricPort, 4)
		}
		if newMetric.Connected {
			newMetric.Uptime = 1 * int64(mi)
		}
		// check device peer to see if WG is working if ping failed
		if !newMetric.Connected {
			if currPeer.ReceiveBytes > 0 &&
				currPeer.TransmitBytes > 0 &&
				time.Now().Before(currPeer.LastHandshakeTime.Add(time.Minute<<1)) {
				newMetric.Connected = true
				newMetric.Uptime = 1 * int64(mi)
			}
		}
		newMetric.TotalTime = 1 * int64(mi)
		metrics.Connectivity[id] = newMetric
	}

	fillUnconnectedData(&metrics, peerMap, mi)
	return &metrics, nil
}

// == used to fill zero value data for non connected peers ==
func fillUnconnectedData(metrics *models.Metrics, peerMap models.PeerMap, mi int) {
	for r := range peerMap {
		id := peerMap[r].ID
		if !metrics.Connectivity[id].Connected {
			newMetric := models.Metric{
				NodeName:  peerMap[r].Name,
				Uptime:    0,
				TotalTime: 1 * int64(mi),
				Connected: false,
				Latency:   999,
				PercentUp: 0,
			}
			metrics.Connectivity[id] = newMetric
		}
	}
}

func extPeerConnStatus(address string) (bool, int64) {
	connected := false
	latency := int64(999)

	slog.Debug("[metrics] checking external peer connectivity", "address", address)
	pinger, err := ping.NewPinger(address)
	if err != nil {
		slog.Warn("could not initiliaze ping for metrics on peer address", "address", address, "err", err)
	} else {
		pinger.SetPrivileged(true)
		pinger.Count = 3
		pinger.Timeout = time.Second * 2
		err = pinger.Run()
		if err != nil {
			slog.Error("failed ping for metrics on peer address", "address", address, "err", err)
		} else {
			pingStats := pinger.Statistics()
			if pingStats.PacketsRecv > 0 {
				latency = pingStats.AvgRtt.Milliseconds()
			}
			if pingStats.PacketLoss == 100 {
				connected = false
			} else {
				connected = true
			}
		}
	}

	slog.Debug("[metrics] external peer connectivity check complete", "address", address, "connected", connected, "latency", latency)
	return connected, latency
}

func PeerConnStatus(address string, port, counter int) (connected bool, latency int64) {
	latency = 999
	if address == "" || port == 0 {
		return
	}

	//ipv6 address adding []
	parseHost := net.ParseIP(address)
	if parseHost.To16() != nil {
		// ipv6
		address = fmt.Sprintf("[%s]", address)
	}

	pinger := tcp_ping.NewTCPing()
	pinger.SetTarget(&tcp_ping.Target{
		Protocol: tcp_ping.TCP,
		Host:     address,
		Port:     port,
		Counter:  4,
		Interval: 1 * time.Second,
		Timeout:  2 * time.Second,
	})
	pingerDone := pinger.Start()
	<-pingerDone
	if pinger.Result() == nil {
		return
	}
	if pinger.Result().SuccessCounter == 0 {
		return
	}
	connected = true
	latency = pinger.Result().Avg().Milliseconds()
	return
}
