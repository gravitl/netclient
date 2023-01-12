package packet

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/gravitl/netmaker/logger"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ConsumeHandshakeInitiationMsg - decodes wg handshake intiation message
func ConsumeHandshakeInitiationMsg(initiator bool, buf []byte, devicePubKey NoisePublicKey, devicePrivKey NoisePrivateKey) (string, error) {

	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)
	var err error
	var msg MessageInitiation
	reader := bytes.NewReader(buf[:])
	err = binary.Read(reader, binary.LittleEndian, &msg)
	if err != nil {
		logger.Log(1, "Failed to decode initiation message")
		return "", err
	}

	if msg.Type != MessageInitiationType {
		return "", errors.New("not handshake initiation message")
	}
	mixHash(&hash, &initialHash, devicePubKey[:])
	mixHash(&hash, &hash, msg.Ephemeral[:])
	mixKey(&chainKey, &initialChainKey, msg.Ephemeral[:])

	// decrypt static key
	var peerPK NoisePublicKey
	var key [chacha20poly1305.KeySize]byte
	ss := sharedSecret(&devicePrivKey, msg.Ephemeral)
	if isZero(ss[:]) {
		return "", errors.New("no secret")
	}
	kdf2(&chainKey, &key, chainKey[:], ss[:])
	aead, _ := chacha20poly1305.New(key[:])
	_, err = aead.Open(peerPK[:0], zeroNonce[:], msg.Static[:], hash[:])
	if err != nil {
		return "", err
	}
	peerKey := base64.StdEncoding.EncodeToString(peerPK[:])
	setZero(hash[:])
	setZero(chainKey[:])
	return peerKey, nil
}

// CreateProxyUpdatePacket - creates proxy update message
func CreateProxyUpdatePacket(msg *ProxyUpdateMessage) ([]byte, error) {
	var buff [MessageProxyUpdateSize]byte
	writer := bytes.NewBuffer(buff[:0])
	err := binary.Write(writer, binary.LittleEndian, msg)
	if err != nil {
		return nil, err
	}
	packet := writer.Bytes()
	return packet, nil

}

// ConsumeProxyUpdateMsg - decodes proxy update message
func ConsumeProxyUpdateMsg(buf []byte) (*ProxyUpdateMessage, error) {
	var msg ProxyUpdateMessage
	reader := bytes.NewReader(buf[:])
	err := binary.Read(reader, binary.LittleEndian, &msg)
	if err != nil {
		logger.Log(1, "Failed to decode proxy update message")
		return nil, err
	}

	if msg.Type != MessageProxyUpdateType {
		return nil, errors.New("not proxy update message")
	}
	return &msg, nil
}

// CreateMetricPacket - creates metric packet
func CreateMetricPacket(id uint32, sender, reciever wgtypes.Key) ([]byte, error) {

	msg := MetricMessage{
		Type:      MessageMetricsType,
		ID:        id,
		Sender:    sender,
		Reciever:  reciever,
		TimeStamp: time.Now().UnixMilli(),
	}
	logger.Log(1, fmt.Sprintf("----------> $$ CREATED PACKET: %+v\n", msg))
	var buff [MessageMetricSize]byte
	writer := bytes.NewBuffer(buff[:0])
	err := binary.Write(writer, binary.LittleEndian, msg)
	if err != nil {
		return nil, err
	}
	packet := writer.Bytes()
	return packet, nil
}

// EncodePacketMetricMsg - encodes metric message to buffer
func EncodePacketMetricMsg(msg *MetricMessage) ([]byte, error) {
	var buff [MessageMetricSize]byte
	writer := bytes.NewBuffer(buff[:0])
	err := binary.Write(writer, binary.LittleEndian, msg)
	if err != nil {
		return nil, err
	}
	packet := writer.Bytes()
	return packet, nil
}

// ConsumeMetricPacket - decodes metric packet
func ConsumeMetricPacket(buf []byte) (*MetricMessage, error) {
	var msg MetricMessage
	var err error
	reader := bytes.NewReader(buf[:])
	err = binary.Read(reader, binary.LittleEndian, &msg)
	if err != nil {
		logger.Log(1, "Failed to decode metric message")
		return nil, err
	}

	if msg.Type != MessageMetricsType {
		return nil, errors.New("not  metric message")
	}
	return &msg, nil
}

// ProcessPacketBeforeSending - encodes data required for proxy transport message
func ProcessPacketBeforeSending(buf []byte, n int, srckey, dstKey string) ([]byte, int, string, string) {
	srcKeymd5 := md5.Sum([]byte(srckey))
	dstKeymd5 := md5.Sum([]byte(dstKey))
	m := ProxyMessage{
		Type:     MessageProxyTransportType,
		Sender:   srcKeymd5,
		Reciever: dstKeymd5,
	}
	var msgBuffer [MessageProxyTransportSize]byte
	writer := bytes.NewBuffer(msgBuffer[:0])
	err := binary.Write(writer, binary.LittleEndian, m)
	if err != nil {
		logger.Log(0, "errror writing msg to bytes: ", err.Error())
		return buf, n, "", ""
	}
	if n > len(buf)-MessageProxyTransportSize {
		buf = append(buf, msgBuffer[:]...)

	} else {
		copy(buf[n:n+MessageProxyTransportSize], msgBuffer[:])
	}
	n += MessageProxyTransportSize

	return buf, n, fmt.Sprintf("%x", srcKeymd5), fmt.Sprintf("%x", dstKeymd5)
}

// ExtractInfo - extracts proxy transport message from the  data buffer
func ExtractInfo(buffer []byte, n int) (int, string, string, error) {
	data := buffer[:n]
	if len(data) < MessageProxyTransportSize {
		return n, "", "", errors.New("proxy message not found")
	}
	var msg ProxyMessage
	var err error
	reader := bytes.NewReader(buffer[n-MessageProxyTransportSize:])
	err = binary.Read(reader, binary.LittleEndian, &msg)
	if err != nil {
		logger.Log(1, "Failed to decode proxy message")
		return n, "", "", err
	}
	if msg.Type != MessageProxyTransportType {
		return n, "", "", errors.New("not a proxy message")
	}
	n -= MessageProxyTransportSize
	return n, fmt.Sprintf("%x", msg.Sender), fmt.Sprintf("%x", msg.Reciever), nil
}
