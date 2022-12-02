package models

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/gravitl/netclient/nm-proxy/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	NmProxyPort = 51722
	DefaultCIDR = "127.0.0.1/8"
)

type ProxyConfig struct {
	RemoteKey           wgtypes.Key
	LocalKey            wgtypes.Key
	WgInterface         *wg.WGIface
	IsExtClient         bool
	PersistentKeepalive *time.Duration
	RecieverChan        chan []byte
	PeerConf            *wgtypes.PeerConfig
	PeerEndpoint        *net.UDPAddr
	RemoteConnAddr      *net.UDPAddr
	LocalConnAddr       *net.UDPAddr
	Network             string
}

type PeerConnMap map[string]*Conn

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

type RemotePeer struct {
	Network             string
	PeerKey             string
	Interface           string
	Endpoint            *net.UDPAddr
	IsExtClient         bool
	IsAttachedExtClient bool
	LocalConn           net.Conn
}

type ExtClientPeer struct {
	CancelFunc context.CancelFunc
	CommChan   chan *net.UDPAddr
}

type WgIfaceConf struct {
	Iface          *wgtypes.Device
	IfaceKeyHash   string
	NetworkPeerMap map[string]PeerConnMap
}
