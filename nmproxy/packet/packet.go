package packet

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gravitl/netmaker/logger"
)

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
		logger.Log(1, "error writing msg to bytes: ", err.Error())
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
