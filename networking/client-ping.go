package networking

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gravitl/netclient/cache"
	"golang.org/x/exp/slog"
)

func tryLocalConnect(peerIp, peerPubKey string, metricsPort int) bool {
	parsePeerIp := net.ParseIP(peerIp)
	if parsePeerIp.To16() != nil {
		// ipv6
		peerIp = fmt.Sprintf("[%s]", peerIp)
	}
	addr := fmt.Sprintf("%s:%d", peerIp, metricsPort)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	message, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && err.Error() != "EOF" {
		return false
	}
	parts := strings.Split(strings.TrimSpace(message), "|")
	if len(parts) == 0 {
		return false
	}

	if parts[0] == messages.Success || parts[0] == peerPubKey {
		return true
	}

	return false

}

// FindBestEndpoint - requests against a given addr and port
func FindBestEndpoint(peerIp, peerPubKey string, peerListenPort, metricsPort int) {
	fmt.Println("=====> hereee 8  CHECKING FOR ", peerIp, peerPubKey, peerListenPort, metricsPort)
	connected := tryLocalConnect(peerIp, peerPubKey, metricsPort)
	fmt.Println("=====> hereee 9  CHECKING FOR ", peerIp, peerPubKey, peerListenPort, metricsPort, connected)
	if connected {
		parsePeerIp := net.ParseIP(peerIp)
		if parsePeerIp.To16() != nil {
			// ipv6
			peerIp = fmt.Sprintf("[%s]", peerIp)
		}
		peerEndpoint, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", peerIp, peerListenPort))
		if err != nil {
			slog.Error("failed to parse peer udp addr", "peeraddr", fmt.Sprintf("%s:%d", peerIp, peerListenPort), "err", err.Error())
			return
		}
		storeNewPeerIface(peerPubKey, peerEndpoint)
	} else {
		if retryCnt, ok := cache.SkipEndpointCache.Load(peerPubKey); ok {
			cnt := retryCnt.(int)
			if cnt <= 3 {
				cnt += 1
				cache.SkipEndpointCache.Store(peerPubKey, cnt)
			}
		} else {
			cache.SkipEndpointCache.Store(peerPubKey, 1)
		}
	}
}
