package dns

import (
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestIsAddrInUse(t *testing.T) {
	if !isAddrInUse(syscall.EADDRINUSE) {
		t.Fatal("expected syscall.EADDRINUSE to match")
	}
	if !isAddrInUse(&net.OpError{Err: syscall.EADDRINUSE}) {
		t.Fatal("expected wrapped EADDRINUSE to match")
	}
	if !isAddrInUse(errors.New("listen udp 100.85.140.1:53: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted.")) {
		t.Fatal("expected Windows bind conflict string to match")
	}
	if !isAddrInUse(errors.New("listen udp 127.0.0.1:53: bind: address already in use")) {
		t.Fatal("expected POSIX bind conflict string to match")
	}
	if isAddrInUse(errors.New("connection refused")) {
		t.Fatal("did not expect unrelated error to match")
	}
	if isAddrInUse(nil) {
		t.Fatal("nil should not match")
	}
}
