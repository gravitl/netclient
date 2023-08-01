package packet

type (

	// MessageType - custom type for message type
	MessageType uint32
)

const (

	// PeerKeyHashSize - constant for peer key hash size
	PeerKeyHashSize = 16

	// MessageProxyTransportSize - constant for proxy transport message size
	MessageProxyTransportSize = 36

	// MessageProxyTransportType - constant for proxy transport message
	MessageProxyTransportType MessageType = 6

	// constant for proxy server buffer size
	DefaultBodySize = 65000 + MessageProxyTransportSize
)
