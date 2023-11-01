package metrics

import (
	"time"

	"github.com/go-ping/ping"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	tcp_ping "github.com/gravitl/tcping/ping"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// Collect - collects metrics
func Collect(network string, peerMap models.PeerMap) (*models.Metrics, error) {
	var metrics models.Metrics
	metrics.Connectivity = make(map[string]models.Metric)
	var wgclient, err = wgctrl.New()
	if err != nil {
		fillUnconnectedData(&metrics, peerMap)
		return &metrics, err
	}
	defer wgclient.Close()
	device, err := wgclient.Device(ncutils.GetInterfaceName())
	if err != nil {
		fillUnconnectedData(&metrics, peerMap)
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
		port := peerMap[currPeer.PublicKey.String()].ListenPort
		isExtClient := peerMap[currPeer.PublicKey.String()].IsExtClient
		if id == "" || address == "" {
			logger.Log(0, "attempted to parse metrics for invalid peer from server", id, address)
			continue
		}

		var newMetric = models.Metric{
			NodeName: peerMap[currPeer.PublicKey.String()].Name,
		}
		logger.Log(2, "collecting metrics for peer", address)
		newMetric.TotalReceived = currPeer.ReceiveBytes
		newMetric.TotalSent = currPeer.TransmitBytes
		if isExtClient {
			newMetric.Connected, newMetric.Latency = extPeerConnStatus(address)
		} else {
			newMetric.Connected, newMetric.Latency = PeerConnStatus(address, port)
		}
		if newMetric.Connected {
			newMetric.Uptime = 1
		}
		// check device peer to see if WG is working if ping failed
		if !newMetric.Connected {
			if currPeer.ReceiveBytes > 0 &&
				currPeer.TransmitBytes > 0 &&
				time.Now().Before(currPeer.LastHandshakeTime.Add(time.Minute<<1)) {
				newMetric.Connected = true
				newMetric.Uptime = 1
			}
		}
		newMetric.TotalTime = 1
		metrics.Connectivity[id] = newMetric
	}

	fillUnconnectedData(&metrics, peerMap)
	return &metrics, nil
}

// == used to fill zero value data for non connected peers ==
func fillUnconnectedData(metrics *models.Metrics, peerMap models.PeerMap) {
	for r := range peerMap {
		id := peerMap[r].ID
		if !metrics.Connectivity[id].Connected {
			newMetric := models.Metric{
				NodeName:  peerMap[r].Name,
				Uptime:    0,
				TotalTime: 1,
				Connected: false,
				Latency:   999,
				PercentUp: 0,
			}
			metrics.Connectivity[id] = newMetric
		}
	}
}

func extPeerConnStatus(address string) (connected bool, latency int64) {
	latency = 999
	pinger, err := ping.NewPinger(address)
	if err != nil {
		logger.Log(0, "could not initiliaze ping for metrics on peer address", address, err.Error())
	} else {
		pinger.SetPrivileged(true)
		pinger.Count = 3
		pinger.Timeout = time.Second * 2
		err = pinger.Run()
		if err != nil {
			logger.Log(0, "failed ping for metrics on peer address", address, err.Error())
		} else {
			pingStats := pinger.Statistics()
			if pingStats.PacketsRecv > 0 {
				latency = pingStats.AvgRtt.Milliseconds()
			}
		}
	}
	return
}

func PeerConnStatus(address string, port int) (connected bool, latency int64) {
	latency = 999
	if address == "" || port == 0 {
		return
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
