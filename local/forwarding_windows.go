//go:build windows
// +build windows

package local

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/exp/slog"
)

// SetIPForwardingWindows enables IP forwarding on the netmaker interface and
// all other connected interfaces (required for Windows egress / internet exit
// and mesh gateway hairpin relay).
func SetIPForwardingWindows() error {
	ifaces := []string{ncutils.GetInterfaceName()}
	if err := EnableForwardingOnInterfaces(ifaces...); err != nil {
		// Interface may not exist yet at early daemon start; Create() re-applies.
		logger.Log(0, "WARNING: Error encountered setting ip forwarding. This can break functionality.")
		slog.Warn("windows: netmaker forwarding not applied yet (iface may be down)", "error", err)
	}
	// Also enable forwarding globally so LAN/WAN ifaces used for egress NAT work
	// even before InsertEgressRoutingRules discovers them.
	if _, err := runPowerShell(`Get-NetIPInterface | Where-Object { $_.ConnectionState -eq 'Connected' } | ForEach-Object { Set-NetIPInterface -InterfaceIndex $_.InterfaceIndex -Forwarding Enabled -ErrorAction SilentlyContinue }`); err != nil {
		slog.Warn("windows global IP forwarding enable had errors", "error", err)
	}
	return nil
}

// EnableForwardingOnInterfaces enables forwarding on the given interface aliases.
// For the netmaker adapter it also enables WeakHostSend/Receive so same-interface
// (gateway/relay hairpin) forwarding works on Windows.
func EnableForwardingOnInterfaces(aliases ...string) error {
	var lastErr error
	nm := ncutils.GetInterfaceName()
	for _, alias := range aliases {
		alias = strings.TrimSpace(alias)
		if alias == "" {
			continue
		}
		escaped := strings.ReplaceAll(alias, "'", "''")
		hairpin := strings.EqualFold(alias, nm)
		var cmd string
		if hairpin {
			// Apply to every AddressFamily row (IPv4 + IPv6). WeakHost* is required
			// for netmaker→netmaker relay; Forwarding alone is not enough.
			cmd = fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$ifaces = Get-NetIPInterface -InterfaceAlias '%s' -ErrorAction Stop
if ($null -eq $ifaces) { throw 'interface not found' }
$ifaces | ForEach-Object {
  Set-NetIPInterface -InterfaceIndex $_.InterfaceIndex -Forwarding Enabled -WeakHostSend Enabled -WeakHostReceive Enabled -ErrorAction Stop
}
`, escaped)
		} else {
			cmd = fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$ifaces = Get-NetIPInterface -InterfaceAlias '%s' -ErrorAction Stop
if ($null -eq $ifaces) { throw 'interface not found' }
$ifaces | ForEach-Object {
  Set-NetIPInterface -InterfaceIndex $_.InterfaceIndex -Forwarding Enabled -ErrorAction Stop
}
`, escaped)
		}
		if _, err := runPowerShell(cmd); err != nil {
			slog.Warn("failed to enable forwarding on interface", "iface", alias, "hairpin", hairpin, "error", err)
			lastErr = err
		} else if hairpin {
			slog.Info("enabled forwarding + weak host on netmaker iface", "iface", alias)
		} else {
			slog.Debug("enabled IP forwarding on interface", "iface", alias)
		}
	}
	return lastErr
}

func runPowerShell(command string) (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
