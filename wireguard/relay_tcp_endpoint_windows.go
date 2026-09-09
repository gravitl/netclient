package wireguard

import (
	"encoding/binary"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
)

// wireguard-go's WinRingEndpoint.DstToString drops the return value in its
// AF_INET branch, so every IPv4 endpoint stringifies to "". That empty string is
// what wireguard-go writes into the UAPI "endpoint=" line, which makes wgctrl
// fail to parse the device (net.ResolveUDPAddr("")) and hides peer endpoints from
// everything that reads them. printableEndpoint restores the real address.
type printableEndpoint struct {
	conn.Endpoint
	dst string
}

func (e printableEndpoint) DstToString() string { return e.dst }

// normalizeEndpoint returns an endpoint whose DstToString renders its address.
func normalizeEndpoint(ep conn.Endpoint) conn.Endpoint {
	if ep == nil {
		return nil
	}
	if ep.DstToString() != "" {
		return ep
	}
	dst := dstFromBytes(ep.DstToBytes())
	if dst == "" {
		return ep
	}
	return printableEndpoint{Endpoint: ep, dst: dst}
}

// rawEndpoint unwraps to the bind's own endpoint type, which WinRingBind.Send
// type-asserts.
func rawEndpoint(ep conn.Endpoint) conn.Endpoint {
	if pe, ok := ep.(printableEndpoint); ok {
		return pe.Endpoint
	}
	return ep
}

func normalizeReceive(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(buf []byte) (int, conn.Endpoint, error) {
		n, ep, err := fn(buf)
		return n, normalizeEndpoint(ep), err
	}
}

// dstFromBytes renders a WinRingEndpoint wire address: the IP followed by the
// port with its bytes swapped out of network order.
func dstFromBytes(b []byte) string {
	if len(b) != 6 && len(b) != 18 {
		return ""
	}
	addr, ok := netip.AddrFromSlice(b[:len(b)-2])
	if !ok {
		return ""
	}
	return netip.AddrPortFrom(addr, binary.LittleEndian.Uint16(b[len(b)-2:])).String()
}
