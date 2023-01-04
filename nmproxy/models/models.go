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

// ProxyAction - type for proxy action
type ProxyAction string

const (
	// default proxy port
	NmProxyPort = 51722
	// default CIDR for proxy peers
	DefaultCIDR = "127.0.0.1/8"
	// PersistentKeepaliveInterval - default keepalive for wg peer
	DefaultPersistentKeepaliveInterval = time.Duration(time.Second * 20)

	// AddNetwork - constant for ADD_NETWORK_TO_PROXY ProxyAction
	AddNetwork ProxyAction = "ADD_NETWORK_TO_PROXY"

	// DeleteNetwork - constant for DELETE_NETWORK_FROM_PROXY ProxyAction
	DeleteNetwork ProxyAction = "DELETE_NETWORK_FROM_PROXY"

	// NoProxy - constant for no ProxyAction
	NoProxy ProxyAction = "NO_PROXY"
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
	WgAddr              net.IP
	Network             string
	ListenPort          int
	ProxyStatus         bool
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
	Address             net.IP
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
	PublicIp     net.IP
	PrivIp       net.IP
	PubPort      int
	PrivPort     int
	ProxyEnabled bool
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
	PublicListenPort       int32        `json:"public_listen_port"`
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

// ProxyManagerPayload - struct for proxy manager payload
type ProxyManagerPayload struct {
	Action          ProxyAction            `json:"action"`
	InterfaceName   string                 `json:"interface_name"`
	Network         string                 `json:"network"`
	WgAddr          string                 `json:"wg_addr"`
	Peers           []wgtypes.PeerConfig   `json:"peers"`
	PeerMap         map[string]PeerConf    `json:"peer_map"`
	IsRelayed       bool                   `json:"is_relayed"`
	IsIngress       bool                   `json:"is_ingress"`
	RelayedTo       *net.UDPAddr           `json:"relayed_to"`
	IsRelay         bool                   `json:"is_relay"`
	RelayedPeerConf map[string]RelayedConf `json:"relayed_conf"`
}

// Metric - struct for metric data
type Metric struct {
	LastRecordedLatency uint64  `json:"last_recorded_latency"`
	ConnectionStatus    bool    `json:"connection_status"`
	TrafficSent         float64 `json:"traffic_sent"`     // stored in MB
	TrafficRecieved     float64 `json:"traffic_recieved"` // stored in MB
}
