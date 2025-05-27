package dns

import (
	"fmt"
	"net"
	"sync"
)

type udpConnPool struct {
	pools sync.Map // map[string]*sync.Pool
}

func newUDPConnPool() *udpConnPool {
	return &udpConnPool{}
}

func (p *udpConnPool) get(serverAddr string) (*net.UDPConn, error) {
	rawPool, _ := p.pools.LoadOrStore(serverAddr, &sync.Pool{
		New: func() any {
			udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
			if err != nil {
				return nil // avoid panics in New
			}
			conn, err := net.DialUDP("udp", nil, udpAddr)
			if err != nil {
				return nil
			}
			return conn
		},
	})

	conn := rawPool.(*sync.Pool).Get()
	if conn == nil {
		return nil, fmt.Errorf("failed to get UDP conn for %s", serverAddr)
	}
	return conn.(*net.UDPConn), nil
}

func (p *udpConnPool) put(serverAddr string, conn *net.UDPConn) {
	if conn == nil {
		return
	}
	if rawPool, ok := p.pools.Load(serverAddr); ok {
		rawPool.(*sync.Pool).Put(conn)
	}
}
