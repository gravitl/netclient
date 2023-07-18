package models

import (
	"context"
	"crypto/md5"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/turn/v2"
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
	PeerPublicKey  wgtypes.Key
	PeerConf       wgtypes.PeerConfig
	PeerEndpoint   *net.UDPAddr
	RemoteConnAddr *net.UDPAddr
	LocalConnAddr  *net.UDPAddr
	TurnConn       net.PacketConn
	UsingTurn      bool
}

// Conn is a peer Connection configuration
type Conn struct {
	// Key is a public key of a remote peer
	Key             wgtypes.Key
	RelayedEndpoint *net.UDPAddr
	Config          Proxy
	StopConn        func()
	ResetConn       func()
	LocalConn       net.Conn
	Mutex           *sync.RWMutex
}

// RemotePeer - struct remote peer data
type RemotePeer struct {
	PeerKey    string
	Endpoint   *net.UDPAddr
	LocalConn  net.Conn
	CancelFunc context.CancelFunc
	CommChan   chan *net.UDPAddr
}

// HostInfo - struct for host information
type HostInfo struct {
	PublicIp     net.IP
	PrivIp       net.IP
	PubPort      int
	PrivPort     int
	ProxyEnabled bool
	NatType      string
}

// ConvPeerKeyToHash - converts peer key to a md5 hash
func ConvPeerKeyToHash(peerKey string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(peerKey)))
}

// Settings - struct for host settings
type Settings struct {
	IsRelay          bool
	IsIngressGateway bool
	IsEgressGateway  bool
	IsRelayed        bool
	RelayedTo        *net.UDPAddr
}

// TurnCfg - struct to hold turn conn details
type TurnCfg struct {
	Mutex    *sync.RWMutex
	Cfg      *turn.ClientConfig
	Client   *turn.Client
	TurnConn net.PacketConn
	Status   bool
}

// PeerConf - struct for peer config in the network
type PeerConf struct {
	Proxy            bool         `json:"proxy"`
	PublicListenPort int32        `json:"public_listen_port"`
	ProxyListenPort  int          `json:"proxy_listen_port"`
	IsExtClient      bool         `json:"is_ext_client"`
	Address          net.IP       `json:"address"`
	IsRelayed        bool         `json:"is_relayed"`
	RelayedTo        *net.UDPAddr `json:"relayed_to"`
	NatType          string       `json:"nat_type"`
}

// TurnPeerCfg - struct for peer turn conn details
type TurnPeerCfg struct {
	Server       string
	PeerConf     PeerConf
	PeerTurnAddr string
}
