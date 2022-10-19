package functions

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/guumaster/hostctl/pkg/file"
	"github.com/guumaster/hostctl/pkg/types"
)

func removeHostDNS(iface string, windows bool) error {
	etchosts := "/etc/hosts"
	temp := os.TempDir()
	lockfile := temp + "/netclient-lock"
	if windows {
		etchosts = "c:\\windows\\system32\\drivers\\etc\\hosts"
		lockfile = temp + "\\netclient-lock"
	}
	if _, err := os.Stat(lockfile); !errors.Is(err, os.ErrNotExist) {
		return errors.New("/etc/hosts file is locked .... aborting")
	}
	lock, err := os.Create(lockfile)
	if err != nil {
		return fmt.Errorf("could not create lock file %w", err)
	}
	lock.Close()
	defer os.Remove(lockfile)
	hosts, err := file.NewFile(etchosts)
	if err != nil {
		return err
	}
	if err := hosts.RemoveProfile(strings.ToLower(iface)); err != nil {
		if err == types.ErrUnknownProfile {
			return nil
		}
		return err
	}
	if err := hosts.Flush(); err != nil {
		return err
	}
	return nil
}
