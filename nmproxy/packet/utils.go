package packet

import (
	"crypto/hmac"
	"crypto/subtle"
	"hash"
	"runtime"

	"github.com/gravitl/netclient/nmproxy/common"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

type (

	// MessageType - custom type for message type
	MessageType uint32

	// ProxyActionType - custom type for proxy update action type
	ProxyActionType uint32

	// NoisePublicKey - custom type for noise public key
	NoisePublicKey [NoisePublicKeySize]byte

	// NoisePrivateKey - custom type for noise private key
	NoisePrivateKey [NoisePrivateKeySize]byte
)

const (
	// NoisePublicKeySize - constant for noise public key size
	NoisePublicKeySize = 32

	// NoisePrivateKeySize - constant for noise private key size
	NoisePrivateKeySize = 32

	// NetworkNameSize - constant for netmaker network name
	NetworkNameSize = 12

	// PeerKeyHashSize - constant for peer key hash size
	PeerKeyHashSize = 16

	// MessageMetricSize - constant for metric message size
	MessageMetricSize = 148

	// MessageProxyUpdateSize - constant for proxy update message size
	MessageProxyUpdateSize = 148

	// MessageProxyTransportSize - constant for proxy transport message size
	MessageProxyTransportSize = 36

	// constants for wg handshake identifiers
	noiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	wGIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	wGLabelMAC1       = "mac1----"
	wGLabelCookie     = "cookie--"

	// MessageTransportType - constant for wg message transport type
	MessageTransportType MessageType = 4

	// MessageInitiationType - constant for wg handshake intiation type
	MessageInitiationType MessageType = 1

	// MessageMetricsType - constant for proxy metrics message
	MessageMetricsType MessageType = 5

	// MessageProxyTransportType - constant for proxy transport message
	MessageProxyTransportType MessageType = 6

	// MessageProxyUpdateType - constant for proxy update message
	MessageProxyUpdateType MessageType = 7

	// UpdateListenPort - constant update listen port proxy action
	UpdateListenPort ProxyActionType = 1
)

func mixKey(dst, c *[blake2s.Size]byte, data []byte) {
	kdf1(dst, c[:], data)
}

func mixHash(dst, h *[blake2s.Size]byte, data []byte) {
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
	hash.Reset()
}

func hmac1(sum *[blake2s.Size]byte, key, in0 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Sum(sum[:0])
}

func hmac2(sum *[blake2s.Size]byte, key, in0, in1 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Write(in1)
	mac.Sum(sum[:0])
}

func kdf1(t0 *[blake2s.Size]byte, key, input []byte) {
	hmac1(t0, key, input)
	hmac1(t0, t0[:], []byte{0x1})
}

func kdf2(t0, t1 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	hmac1(&prk, key, input)
	hmac1(t0, prk[:], []byte{0x1})
	hmac2(t1, prk[:], t0[:], []byte{0x2})
	setZero(prk[:])
}

func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}
func isZero(val []byte) bool {
	acc := 1
	for _, b := range val {
		acc &= subtle.ConstantTimeByteEq(b, 0)
	}
	return acc == 1
}

func sharedSecret(sk *NoisePrivateKey, pk NoisePublicKey) (ss [NoisePublicKeySize]byte) {
	apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarMult(&ss, ask, apk)
	return ss
}

// TurnOffIpFowarding - turns off ip fowarding, runs only for linux systems
func TurnOffIpFowarding() {
	if runtime.GOOS == "linux" {
		_, err := common.RunCmd("sysctl -w net.ipv4.ip_forward=0", true)
		if err != nil {
			logger.Log(0, "error encountered turning off ip forwarding: ", err.Error())
		}
	}
}
