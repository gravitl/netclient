package models

import (
	"context"
	"crypto/md5"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	// default proxy port
	NmProxyPort = 51722
	// default CIDR for proxy peers
	DefaultCIDR = "127.0.0.1/8"
	// PersistentKeepaliveInterval - default keepalive for wg peer
	DefaultPersistentKeepaliveInterval = time.Duration(time.Second * 20)
)

// PeerConnMap - type for peer conn config map
type PeerConnMap map[string]*Conn

// Proxy - struct for proxy config
type Proxy struct {
	RemoteKey           wgtypes.Key
	LocalKey            wgtypes.Key
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
	Config              Proxy
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

// HostInfo - struct for host information
type HostInfo struct {
	PublicIp net.IP
	PrivIp   net.IP
	PubPort  int
	PrivPort int
}

// RelayedConf - struct relayed peers config
type RelayedConf struct {
	RelayedPeerEndpoint *net.UDPAddr         `json:"relayed_peer_endpoint"`
	RelayedPeerPubKey   string               `json:"relayed_peer_pub_key"`
	Peers               []wgtypes.PeerConfig `json:"relayed_peers"`
}

// PeerConf - struct for peer config in the network
type PeerConf struct {
	IsExtClient            bool         `json:"is_ext_client"`
	Address                net.IP       `json:"address"`
	ExtInternalIp          net.IP       `json:"ext_internal_ip"`
	IsAttachedExtClient    bool         `json:"is_attached_ext_client"`
	IngressGatewayEndPoint *net.UDPAddr `json:"ingress_gateway_endpoint"`
	IsRelayed              bool         `json:"is_relayed"`
	RelayedTo              *net.UDPAddr `json:"relayed_to"`
	Proxy                  bool         `json:"proxy"`
	ProxyListenPort        int32        `json:"proxy_listen_port"`
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
