package metrics

import (
	"fmt"
	"time"

	"github.com/go-ping/ping"
	"github.com/gravitl/netmaker/logger"
)

const MetricCollectionInterval = time.Second * 25

// PeerConnectionStatus - get peer connection status by pinging
func PeerConnectionStatus(address string) (connected bool) {
	fmt.Println("PINGER ADDR: ", address)
	pinger, err := ping.NewPinger(address)
	if err != nil {
		logger.Log(0, "could not initiliaze ping peer address", address, err.Error())
		connected = false
	} else {
		pinger.Timeout = time.Second * 2
		err = pinger.Run()
		if err != nil {
			logger.Log(0, "failed to ping on peer address", address, err.Error())
			return false
		} else {
			pingStats := pinger.Statistics()
			if pingStats.PacketsRecv > 0 {
				connected = true
				return
			}
		}
	}

	return
}
