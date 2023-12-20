package functions

import (
	"fmt"
	"os"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/txeh"
	"github.com/guumaster/hostctl/pkg/file"
	"github.com/guumaster/hostctl/pkg/types"
)

const etcHostsComment = "netmaker"

// removeHostDNS -remove dns entries from /etc/hosts using hostctl
// this function should only be called from the migrate function
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

func deleteAllDNS() error {
	temp := os.TempDir()
	lockfile := temp + "/netclient-lock"
	if err := config.Lock(lockfile); err != nil {
		return err
	}
	defer config.Unlock(lockfile)
	hosts, err := txeh.NewHostsDefault()
	if err != nil {
		return err
	}
	lines := hosts.GetHostFileLines()
	addressesToDelete := []string{}
	for _, line := range *lines {
		if line.Comment == etcHostsComment {
			addressesToDelete = append(addressesToDelete, line.Address)
		}
	}
	hosts.RemoveAddresses(addressesToDelete, etcHostsComment)
	if err := hosts.Save(); err != nil {
		return err
	}
	return nil
}
