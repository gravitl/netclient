//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package wireguard

import (
	"errors"
	"syscall"
)

func isEconnRefused(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && errors.Is(errno, syscall.ECONNREFUSED)
}
