package config

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"

	"github.com/gravitl/netmaker/logger"
)

type resolvconfFlavor int

const (
	systemdStub resolvconfFlavor = iota
	systemdUplink
	resolvconf
	openresolv
	file
	unknown
)

func NewManager(opts ...ManagerOption) (Manager, error) {
	flavor, err := getResolvconfFlavor()
	if err != nil {
		return nil, err
	}

	switch flavor {
	case systemdStub:
		logger.Log(0, "creating systemd stub manager")
		return newSystemdStubManager(opts...)
	case systemdUplink:
		logger.Log(0, "creating systemd uplink manager")
		return newSystemdUplinkManager(opts...)
	case resolvconf:
		logger.Log(0, "creating resolvconf manager")
		return newResolvconfManager(opts...)
	case openresolv:
		logger.Log(0, "creating openresolv manager")
		return newOpenresolvManager(opts...)
	default:
		logger.Log(0, "creating file manager")
		return newFileManager(opts...)
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

		if strings.HasSuffix(target, "/run/systemd/resolve/stub-resolv.conf") {
			return systemdStub, nil
		} else if strings.HasSuffix(target, "/run/systemd/resolve/resolv.conf") {
			return systemdUplink, nil
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
