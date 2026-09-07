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
// all other IPv4/IPv6 interfaces (required for Windows egress / internet exit).
func SetIPForwardingWindows() error {
	ifaces := []string{ncutils.GetInterfaceName()}
	if err := EnableForwardingOnInterfaces(ifaces...); err != nil {
		logger.Log(0, "WARNING: Error encountered setting ip forwarding. This can break functionality.")
		return err
	}
	// Also enable forwarding globally so LAN/WAN ifaces used for egress NAT work
	// even before InsertEgressRoutingRules discovers them.
	if _, err := runPowerShell(`Get-NetIPInterface | Where-Object { $_.ConnectionState -eq 'Connected' } | ForEach-Object { Set-NetIPInterface -InterfaceIndex $_.InterfaceIndex -Forwarding Enabled -ErrorAction SilentlyContinue }`); err != nil {
		slog.Warn("windows global IP forwarding enable had errors", "error", err)
	}
	return nil
}

// EnableForwardingOnInterfaces enables forwarding on the given interface aliases.
func EnableForwardingOnInterfaces(aliases ...string) error {
	var lastErr error
	for _, alias := range aliases {
		alias = strings.TrimSpace(alias)
		if alias == "" {
			continue
		}
		escaped := strings.ReplaceAll(alias, "'", "''")
		cmd := fmt.Sprintf(`Set-NetIPInterface -InterfaceAlias '%s' -Forwarding Enabled -ErrorAction Stop`, escaped)
		if _, err := runPowerShell(cmd); err != nil {
			slog.Warn("failed to enable forwarding on interface", "iface", alias, "error", err)
			lastErr = err
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
