//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package wireguard

import "golang.zx2c4.com/wireguard/conn"

// Only the Windows bind needs its endpoints wrapped; see the windows build of
// this file.
func normalizeEndpoint(ep conn.Endpoint) conn.Endpoint { return ep }

func rawEndpoint(ep conn.Endpoint) conn.Endpoint { return ep }

func normalizeReceive(fn conn.ReceiveFunc) conn.ReceiveFunc { return fn }
