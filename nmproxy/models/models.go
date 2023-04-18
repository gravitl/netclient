package models

import (
	"context"
	"crypto/md5"
	"fmt"
	"net"
	"sync"

	nm_models "github.com/gravitl/netmaker/models"
	"github.com/pion/turn"
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
	PeerPublicKey   wgtypes.Key
	IsExtClient     bool
	PeerConf        wgtypes.PeerConfig
	PeerEndpoint    *net.UDPAddr
	RemoteConnAddr  *net.UDPAddr
	LocalConnAddr   *net.UDPAddr
	ListenPort      int
	ProxyListenPort int
	ProxyStatus     bool
	UsingTurn       bool
}

// Conn is a peer Connection configuration
type Conn struct {
	// Key is a public key of a remote peer
	Key             wgtypes.Key
	IsRelayed       bool
	RelayedEndpoint *net.UDPAddr
	Config          Proxy
	StopConn        func(bool)
	ResetConn       func()
	LocalConn       net.Conn
	Mutex           *sync.RWMutex
	NetworkSettings map[string]Settings
	ServerMap       map[string]struct{}
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

type TurnCfg struct {
	Cfg      *turn.ClientConfig
	Client   *turn.Client
	TurnConn net.PacketConn
}

type TurnPeerCfg struct {
	Server       string
	PeerConf     nm_models.PeerConf
	PeerTurnAddr string
}
