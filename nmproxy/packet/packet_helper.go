package packet

// ProxyMessage - struct for proxy message
type ProxyMessage struct {
	Type     MessageType
	Sender   [PeerKeyHashSize]byte
	Reciever [PeerKeyHashSize]byte
}
