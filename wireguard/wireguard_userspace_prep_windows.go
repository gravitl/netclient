//go:build windows
// +build windows

package wireguard

import (
	"github.com/gravitl/netclient/config"
	"golang.org/x/exp/slog"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/driver"
)

// prepareUserspaceTUN closes any WireGuardNT adapter holding the iface name and
// sets a stable Wintun GUID so CreateTUN can own "netmaker".
func prepareUserspaceTUN(nc *NCIface) {
	idString := ""
	if cfg := config.Netclient(); cfg != nil {
		idString = cfg.Host.ID.String()
	}
	if idString == "" {
		idString = config.DefaultHostID
	}
	if guid, err := windows.GUIDFromString("{" + idString + "}"); err == nil {
		tun.WintunStaticRequestedGUID = &guid
	} else {
		slog.Warn("tcp uplink: failed to set Wintun GUID", "error", err)
	}

	if adapter, err := driver.OpenAdapter(nc.Name); err == nil {
		slog.Info("tcp uplink: closing WireGuardNT adapter before userspace Wintun", "iface", nc.Name)
		if closeErr := adapter.Close(); closeErr != nil {
			slog.Warn("tcp uplink: WireGuardNT Close failed", "error", closeErr)
		}
	}
}
