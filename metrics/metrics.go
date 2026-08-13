package metrics

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	//lint:ignore SA1019 Reason: will be switching to a alternative package
	"github.com/go-ping/ping"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	tcp_ping "github.com/gravitl/tcping/ping"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// defaultProbeConcurrency caps the number of parallel per-peer probes inside
// Collect. Each probe holds raw ICMP and/or TCP sockets for up to several
// seconds, so we bound concurrency to avoid exhausting file descriptors on
// hosts with many peers. Override via NETCLIENT_METRICS_CONCURRENCY.
const defaultProbeConcurrency = 32

// Collect - collects metrics. Per-peer probes run in parallel (bounded by
// probeConcurrency()) so a slow or unreachable peer does not delay the rest.
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

	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		sem = make(chan struct{}, probeConcurrency())
	)

	wgPeers := make(map[string]int)
	for i, peer := range device.Peers {
		wgPeers[peer.PublicKey.String()] = i
	}
	for pubKey := range peerMap {
		var wgPeer wgtypes.Peer
		index, ok := wgPeers[pubKey]
		if ok {
			wgPeer = device.Peers[index]
		}

		peer := peerMap[pubKey]
		if peer.ID == "" || peer.Address == "" {
			logger.Log(0, "attempted to parse metrics for invalid peer from server", peer.ID, peer.Address)
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			newMetric := models.Metric{
				NodeName:      peer.Name,
				TotalReceived: wgPeer.ReceiveBytes,
				TotalSent:     wgPeer.TransmitBytes,
			}
			if peer.IsExtClient {
				newMetric.Connected, newMetric.Latency = ExtPeerConnStatus(peer.Address, 3)
			} else {
				newMetric.Connected, newMetric.Latency = PeerConnStatus(peer.Address, metricPort, 4)
			}
			if newMetric.Connected {
				newMetric.Uptime = int64(mi)
			}
			// fall back to recent-handshake heuristic if the active probe failed
			if !newMetric.Connected {
				if wgPeer.ReceiveBytes > 0 &&
					wgPeer.TransmitBytes > 0 &&
					time.Now().Before(wgPeer.LastHandshakeTime.Add(time.Minute<<1)) {
					newMetric.Connected = true
					newMetric.Uptime = int64(mi)
				}
			}
			newMetric.TotalTime = int64(mi)

			mu.Lock()
			metrics.Connectivity[peer.ID] = newMetric
			mu.Unlock()
		}()
	}
	wg.Wait()

	fillUnconnectedData(&metrics, peerMap, mi)
	return &metrics, nil
}

// probeConcurrency returns the maximum number of per-peer probes Collect runs
// in parallel. NETCLIENT_METRICS_CONCURRENCY overrides the default; values
// <= 0 or unparsable fall back to defaultProbeConcurrency.
func probeConcurrency() int {
	if v := os.Getenv("NETCLIENT_METRICS_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultProbeConcurrency
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

func ExtPeerConnStatus(address string, count int) (bool, int64) {
	connected := false
	latency := int64(999)

	slog.Debug("[metrics] checking external peer connectivity", "address", address)
	pinger, err := ping.NewPinger(address)
	if err != nil {
		slog.Debug("could not initiliaze ping for metrics on peer address", "address", address, "err", err)
	} else {
		if count <= 0 {
			count = 3
		}
		pinger.SetPrivileged(true)
		pinger.Count = count
		pinger.Timeout = time.Second * 2
		err = pinger.Run()
		if err != nil {
			slog.Debug("failed ping for metrics on peer address", "address", address, "err", err)
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

	if counter <= 0 {
		counter = 4
	}

	pinger := tcp_ping.NewTCPing()
	pinger.SetTarget(&tcp_ping.Target{
		Protocol: tcp_ping.TCP,
		Host:     address,
		Port:     port,
		Counter:  counter,
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
