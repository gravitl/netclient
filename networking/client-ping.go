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
	if parsePeerIp.To4() == nil {
		// ipv6
		peerIp = fmt.Sprintf("[%s]", peerIp)
	}
	var conn net.Conn
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	var err error
	for i := 0; i < 5; i++ {
		addr := fmt.Sprintf("%s:%d", peerIp, metricsPort)
		conn, err = net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			continue
		}
		message, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil && err.Error() != "EOF" {
			continue
		}
		parts := strings.Split(strings.TrimSpace(message), "|")
		if len(parts) == 0 {
			continue
		}
		if parts[0] == messages.Success || parts[0] == peerPubKey {
			return true
		}
		time.Sleep(time.Second * 5)
	}
	return false

}

// FindBestEndpoint - requests against a given addr and port
func FindBestEndpoint(peerIp, peerPubKey string, peerListenPort, metricsPort int) {
	connected := tryLocalConnect(peerIp, peerPubKey, metricsPort)
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
