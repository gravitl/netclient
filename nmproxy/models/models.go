package models

import (
	"context"
	"crypto/md5"
	"fmt"
	"net"
	"sync"

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

// Proxy - struct for proxy config
type Proxy struct {
	PeerPublicKey  wgtypes.Key
	IsExtClient    bool
	PeerConf       wgtypes.PeerConfig
	PeerEndpoint   *net.UDPAddr
	RemoteConnAddr *net.UDPAddr
	LocalConnAddr  *net.UDPAddr
	ListenPort     int
	ProxyStatus    bool
}

// Conn is a peer Connection configuration
type Conn struct {
	// Key is a public key of a remote peer
	Key             wgtypes.Key
	IsExtClient     bool
	IsRelayed       bool
	RelayedEndpoint *net.UDPAddr
	Config          Proxy
	StopConn        func()
	ResetConn       func()
	LocalConn       net.Conn
	Mutex           *sync.RWMutex
	NetworkSettings map[string]Settings
	ServerMap       map[string]struct{}
}

// RemotePeer - struct remote peer data
type RemotePeer struct {
	PeerKey     string
	Endpoint    *net.UDPAddr
	IsExtClient bool
	LocalConn   net.Conn
	CancelFunc  context.CancelFunc
	CommChan    chan *net.UDPAddr
}

// HostInfo - struct for host information
type HostInfo struct {
	PublicIp     net.IP
	PrivIp       net.IP
	PubPort      int
	PrivPort     int
	ProxyEnabled bool
}

// ConvPeerKeyToHash - converts peer key to a md5 hash
func ConvPeerKeyToHash(peerKey string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(peerKey)))
}

// IsPublicIP indicates whether IP is public or not.
func IsPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return false
	}
	return true
}

// Settings - struct for host settings
type Settings struct {
	IsRelay          bool
	IsIngressGateway bool
	IsEgressGateway  bool
	IsRelayed        bool
	RelayedTo        *net.UDPAddr
}
