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
		// If pool returned nil, create a new connection directly
		udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve UDP addr for %s: %w", serverAddr, err)
		}
		udpConn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to dial UDP for %s: %w", serverAddr, err)
		}
		return udpConn, nil
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

// closeConnection closes a connection without putting it back in the pool
// This is used when a connection fails and we want to ensure a fresh one is created next time
func (p *udpConnPool) closeConnection(conn *net.UDPConn) {
	if conn != nil {
		conn.Close()
	}
}
