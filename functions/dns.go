package functions

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gravitl/netclient/ncutils"
	"github.com/guumaster/hostctl/pkg/file"
	"github.com/guumaster/hostctl/pkg/parser"
	"github.com/guumaster/hostctl/pkg/types"
)

func removeHostDNS(network string) error {
	etchosts := "/etc/hosts"
	temp := os.TempDir()
	lockfile := temp + "/netclient-lock"
	if ncutils.IsWindows() {
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
	if err := hosts.RemoveProfile(strings.ToLower(network)); err != nil {
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

func setHostDNS(dns, network string) error {
	etchosts := "/etc/hosts"
	temp := os.TempDir()
	lockfile := temp + "/netclient-lock"
	if ncutils.IsWindows() {
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
	dnsdata := strings.NewReader(dns)
	profile, err := parser.ParseProfile(dnsdata)
	if err != nil {
		return err
	}
	hosts, err := file.NewFile(etchosts)
	if err != nil {
		return err
	}
	profile.Name = strings.ToLower(network)
	profile.Status = types.Enabled
	if err := hosts.ReplaceProfile(profile); err != nil {
		return err
	}
	if err := hosts.Flush(); err != nil {
		return err
	}
	return nil
}
