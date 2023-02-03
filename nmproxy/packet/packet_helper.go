package packet

import (
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.zx2c4.com/wireguard/tai64n"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const poly1305TagSize = 16

var (
	initialChainKey [blake2s.Size]byte
	initialHash     [blake2s.Size]byte
	zeroNonce       [chacha20poly1305.NonceSize]byte
)

func init() {
	initialChainKey = blake2s.Sum256([]byte(noiseConstruction))
	mixHash(&initialHash, &initialChainKey, []byte(wGIdentifier))
}

// MessageInitiation - struct for wg handshake initiation message
type MessageInitiation struct {
	Type      MessageType
	Sender    uint32
	Ephemeral NoisePublicKey
	Static    [NoisePublicKeySize + poly1305TagSize]byte
	Timestamp [tai64n.TimestampSize + poly1305TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

// MetricMessage - struct for metric message
type MetricMessage struct {
	Type      MessageType
	ID        uint32
	Reply     uint32
	Sender    wgtypes.Key
	Reciever  wgtypes.Key
	TimeStamp int64
}

// ProxyMessage - struct for proxy message
type ProxyMessage struct {
	Type     MessageType
	Sender   [PeerKeyHashSize]byte
	Reciever [PeerKeyHashSize]byte
}

// ProxyUpdateMessage - struct for proxy update message
type ProxyUpdateMessage struct {
	Type       MessageType
	Action     ProxyActionType
	Sender     wgtypes.Key
	Reciever   wgtypes.Key
	ListenPort uint32
}
