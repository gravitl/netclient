package models

import (
	"context"
	"crypto/md5"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gravitl/netclient/nm-proxy/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	// default proxy port
	NmProxyPort = 51722
	// default CIDR for proxy peers
	DefaultCIDR = "127.0.0.1/8"
)

// PeerConnMap - type for peer conn config map
type PeerConnMap map[string]*Conn

// ProxyConfig - struct for proxy config
type ProxyConfig struct {
	RemoteKey           wgtypes.Key
	LocalKey            wgtypes.Key
	WgInterface         *wg.WGIface
	IsExtClient         bool
	PersistentKeepalive *time.Duration
	PeerConf            *wgtypes.PeerConfig
	PeerEndpoint        *net.UDPAddr
	RemoteConnAddr      *net.UDPAddr
	LocalConnAddr       *net.UDPAddr
	Network             string
}

// Conn is a peer Connection configuration
type Conn struct {

	// Key is a public key of a remote peer
	Key                 wgtypes.Key
	IsExtClient         bool
	IsRelayed           bool
	RelayedEndpoint     *net.UDPAddr
	IsAttachedExtClient bool
	Config              ProxyConfig
	StopConn            func()
	ResetConn           func()
	LocalConn           net.Conn
	Mutex               *sync.RWMutex
}

// RemotePeer - struct remote peer data
type RemotePeer struct {
	Network             string
	PeerKey             string
	Interface           string
	Endpoint            *net.UDPAddr
	IsExtClient         bool
	IsAttachedExtClient bool
	LocalConn           net.Conn
	CancelFunc          context.CancelFunc
	CommChan            chan *net.UDPAddr
}

// ConvPeerKeyToHash - converts peer key to a md5 hash
func ConvPeerKeyToHash(peerKey string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(peerKey)))
}
