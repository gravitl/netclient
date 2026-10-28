//go:build windows
// +build windows

package local

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/exp/slog"
)

// SetIPForwardingWindows enables IP forwarding on the netmaker interface only.
// LAN/WAN ifaces used for egress NAT are enabled later by InsertEgressRoutingRules
// when those ranges are known — never blanket-enable all Connected ifaces (that
// can routing-loop with exit-node 0.0.0.0/0 when underlay pins are missing).
func SetIPForwardingWindows() error {
	nm := ncutils.GetInterfaceName()
	// This runs before the adapter exists on a normal start; wireguard Create()
	// applies Forwarding/WeakHost* once it is up. Only warn when the adapter is
	// present and the call still fails, so the warning always means something.
	if _, err := net.InterfaceByName(nm); err != nil {
		slog.Debug("windows: netmaker iface not up yet; forwarding applied at iface create", "iface", nm)
	} else if err := EnableForwardingOnInterfaces(nm); err != nil {
		logger.Log(0, "WARNING: Error encountered setting ip forwarding. This can break functionality.")
		slog.Warn("windows: failed to enable forwarding on netmaker iface", "iface", nm, "error", err)
	}
	return nil
}

// EnableForwardingOnInterfaces enables forwarding on the given interface aliases.
// For the netmaker adapter it also enables WeakHostSend/Receive so same-interface
// (gateway/relay hairpin) forwarding works on Windows.
func EnableForwardingOnInterfaces(aliases ...string) error {
	return setForwardingOnInterfaces(true, aliases...)
}

// DisableForwardingOnInterfaces disables forwarding on the given interface aliases.
// For the netmaker adapter it also disables WeakHostSend/Receive. Missing ifaces
// are ignored so stop/FlushAll stay safe after the adapter is already torn down.
func DisableForwardingOnInterfaces(aliases ...string) error {
	return setForwardingOnInterfaces(false, aliases...)
}

func setForwardingOnInterfaces(enable bool, aliases ...string) error {
	var lastErr error
	nm := ncutils.GetInterfaceName()
	fwd := "Disabled"
	weak := "Disabled"
	action := "disable"
	if enable {
		fwd = "Enabled"
		weak = "Enabled"
		action = "enable"
	}
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
  Set-NetIPInterface -InterfaceIndex $_.InterfaceIndex -Forwarding %s -WeakHostSend %s -WeakHostReceive %s -ErrorAction Stop
}
`, escaped, fwd, weak, weak)
		} else {
			cmd = fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$ifaces = Get-NetIPInterface -InterfaceAlias '%s' -ErrorAction Stop
if ($null -eq $ifaces) { throw 'interface not found' }
$ifaces | ForEach-Object {
  Set-NetIPInterface -InterfaceIndex $_.InterfaceIndex -Forwarding %s -ErrorAction Stop
}
`, escaped, fwd)
		}
		if _, err := runPowerShell(cmd); err != nil {
			// Adapter may already be gone on stop/FlushAll.
			if !enable && strings.Contains(strings.ToLower(err.Error()), "not found") {
				slog.Debug("windows: iface gone while disabling forwarding", "iface", alias)
				continue
			}
			slog.Warn("failed to "+action+" forwarding on interface", "iface", alias, "hairpin", hairpin, "error", err)
			lastErr = err
		} else if hairpin {
			slog.Info(action+"d forwarding + weak host on netmaker iface", "iface", alias)
		} else {
			slog.Debug(action+"d IP forwarding on interface", "iface", alias)
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
