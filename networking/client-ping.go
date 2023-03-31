package networking

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func IsBridgeNetwork(iface models.Iface) bool {

	l, err := netlink.LinkByName(iface.Name)
	if err != nil {
		return false
	}
	if _, ok := l.(*netlink.Bridge); ok {
		logger.Log(1, fmt.Sprintf("Interface is a bridge network: %+v", iface))
		return true
	}
	return false
}

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
	c, err := net.DialTimeout("tcp", net.JoinHostPort(reqAddr, strconv.Itoa(proxyPort)), reqTimeout)
	if err != nil {
		return err
	}
	defer c.Close()
	sentTime := time.Now().UnixMilli()
	msg := bestIfaceMsg{
		Hash:      fmt.Sprintf("%v", sha1.Sum([]byte(currentHostPubKey))),
		TimeStamp: sentTime,
	}
	reqData, err := json.Marshal(&msg)
	if err != nil {
		return err
	}
	_, err = c.Write(reqData)
	if err != nil {
		return err
	}
	if err = c.SetReadDeadline(time.Now().Add(reqTimeout)); err != nil {
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
		if err = storeNewPeerIface(fmt.Sprintf("%v", sha1.Sum([]byte(peerPubKey))), peerAddr, time.Duration(latency)); err != nil {
			return err
		}
	}
	return fmt.Errorf(response)
}
