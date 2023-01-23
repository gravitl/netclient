package functions

import (
	"fmt"
	"os"
	"strings"

	"github.com/gravitl/netclient/config"
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
	if err := config.Lock(lockfile); err != nil {
		return fmt.Errorf("could not create lock file %w", err)
	}
	defer config.Unlock(lockfile)
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
	if err := config.Lock(lockfile); err != nil {
		return fmt.Errorf("could not create lock file %w", err)
	}
	defer config.Unlock(lockfile)
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
