package cache

import (
	"os"
	"strings"
)

type cacheManagerFlavor int

const (
	systemd cacheManagerFlavor = iota
	noop
)

func NewManager() Manager {
	flavor, _ := getResolvconfFlavor()

	switch flavor {
	case systemd:
		return newSystemdManager()
	default:
		return newNoopManager()
	}
}

func getResolvconfFlavor() (cacheManagerFlavor, error) {
	stat, err := os.Lstat("/etc/resolv.conf")
	if err != nil {
		return noop, err
	}

	if stat.Mode()&os.ModeSymlink == os.ModeSymlink {
		target, err := os.Readlink("/etc/resolv.conf")
		if err != nil {
			return noop, err
		}

		if strings.HasSuffix(target, "/run/systemd/resolve/stub-resolv.conf") ||
			strings.HasSuffix(target, "/run/systemd/resolve/resolv.conf") {
			return systemd, nil
		}
	}

	return noop, nil
}
