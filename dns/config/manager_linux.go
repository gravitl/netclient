package config

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
)

type resolvconfFlavor int

const (
	systemd resolvconfFlavor = iota
	resolvconf
	openresolv
	file
	unknown
)

func NewManager() (Manager, error) {
	flavor, err := getResolvconfFlavor()
	if err != nil {
		return nil, err
	}

	switch flavor {
	case systemd:
		return newSystemdManager()
	case resolvconf:
		return newResolvconfManager()
	case openresolv:
		return newOpenresolvManager()
	default:
		return newFileManager()
	}
}

func getResolvconfFlavor() (resolvconfFlavor, error) {
	stat, err := os.Lstat("/etc/resolv.conf")
	if err != nil {
		return unknown, err
	}

	if stat.Mode()&os.ModeSymlink == os.ModeSymlink {
		target, err := os.Readlink("/etc/resolv.conf")
		if err != nil {
			return unknown, err
		}

		if strings.HasSuffix(target, "/run/systemd/resolve/stub-resolv.conf") ||
			strings.HasSuffix(target, "/run/systemd/resolve/resolv.conf") {
			return systemd, nil
		}
	}

	_, err = exec.LookPath("resolvconf")
	if err != nil {
		var execErr *exec.Error
		if errors.As(err, &execErr) && errors.Is(execErr.Err, exec.ErrNotFound) {
			return file, nil
		}

		return unknown, err
	}

	output, err := exec.Command("resolvconf", "--version").CombinedOutput()
	if err != nil {
		var execErr *exec.ExitError
		if errors.As(err, &execErr) && execErr.ExitCode() == 99 {
			return resolvconf, nil
		}
	}

	if bytes.HasPrefix(output, []byte("Debian resolvconf")) {
		return resolvconf, nil
	}

	return openresolv, nil
}
