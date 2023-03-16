package networking

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// FindBestEndpoint - requests against a given addr and port
func FindBestEndpoint(reqAddr, currentHostPubKey, peerPubKey, serverName string, proxyPort int) error {
	peerAddr, err := netip.ParseAddr(reqAddr) // begin validate
	if err != nil {
		return err
	}
	if _, err = wgtypes.ParseKey(peerPubKey); err != nil {
		return err
	}
	if _, err = wgtypes.ParseKey(currentHostPubKey); err != nil {
		return err
	}
	if len(serverName) == 0 {
		return fmt.Errorf("no server provided")
	} // end validate
	c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", reqAddr, proxyPort), reqTimeout)
	if err != nil { // TODO: change verbosity for timeouts (probably frequent)
		return err
	}
	defer c.Close()
	sentTime := time.Now().UnixMilli()
	msg := strings.Join([]string{
		currentHostPubKey,
		serverName,
		strconv.Itoa(int(sentTime)),
	}, messages.Delimiter)
	_, err = c.Write([]byte(msg))
	if err != nil {
		return err
	}
	if err = c.SetReadDeadline(time.Now().Add(time.Second * 5)); err != nil {
		return err
	}
	buf := make([]byte, 1024)
	numBytes, err := c.Read(buf)
	if err != nil {
		return err
	}
	latency := time.Now().UnixMilli() - sentTime
	response := string(buf[:numBytes])
	if response == messages.Success { // found new best interface, save it
		if err = storeNewPeerIface(peerPubKey, serverName, peerAddr, time.Duration(latency)); err != nil {
			return err
		}
	}
	return fmt.Errorf(response)
}
