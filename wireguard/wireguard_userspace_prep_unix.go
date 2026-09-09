//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package wireguard

func prepareUserspaceTUN(nc *NCIface) {}
