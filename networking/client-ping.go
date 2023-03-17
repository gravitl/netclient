package networking

import (
	"crypto/sha1"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// FindBestEndpoint - requests against a given addr and port
func FindBestEndpoint(reqAddr, currentHostPubKey, peerPubKey string, proxyPort int) error {
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
	c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", reqAddr, proxyPort), reqTimeout)
	if err != nil { // TODO: change verbosity for timeouts (probably frequent)
		return err
	}
	defer c.Close()
	sentTime := time.Now().UnixMilli()
	hsha1 := sha1.Sum([]byte(currentHostPubKey))
	msg := strings.Join([]string{
		string(hsha1[:]),
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
		if err = storeNewPeerIface(peerPubKey, peerAddr, time.Duration(latency)); err != nil {
			return err
		}
	}
	return fmt.Errorf(response)
}
