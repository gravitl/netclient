package posture

import (
	"bufio"
	"context"
	"strings"
	"time"
)

// collectPlatform fills Windows-specific identity fields:
//   - SerialNumber / HardwareUUID via PowerShell Get-CimInstance, with registry
//     and wmic fallbacks that work when netclient runs as a SYSTEM service
//   - EntraDeviceID via `dsregcmd /status`, with registry fallbacks for
//     workplace-joined hosts (dsregcmd hides user join state from services)
//
// EntraDeviceID prefers Azure AD join DeviceId; when the host is only
// workplace-joined, WorkplaceDeviceId (or its JoinInfo registry key) is used.
//
// Each probe is best-effort and leaves the field empty on failure.
func collectPlatform(id *DeviceIdentity, r runner) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	id.SerialNumber = firstNonEmptyString(
		runPowerShell(ctx, r, "(Get-CimInstance Win32_BIOS).SerialNumber"),
		readLocalMachineStringValue(biosRegPath, "SystemSerialNumber"),
	)
	id.HardwareUUID = firstNonEmptyString(
		sanitizeHardwareUUID(runPowerShell(ctx, r, "(Get-CimInstance Win32_ComputerSystemProduct).UUID")),
		sanitizeHardwareUUID(runWmicValue(ctx, r, "csproduct", "uuid")),
		sanitizeHardwareUUID(readLocalMachineStringValue(biosRegPath, "SystemProductGuid")),
	)

	entraID := ""
	if out, err := r.Run(ctx, "dsregcmd", "/status"); err == nil && out != "" {
		entraID = extractEntraDeviceID(out)
	}
	id.EntraDeviceID = firstNonEmptyString(entraID, readJoinInfoFromRegistry())
}

// extractEntraDeviceID returns the Azure AD device object ID when present,
// otherwise the workplace-join device ID for work/school account enrollment.
func extractEntraDeviceID(blob string) string {
	if id := extractDsregcmdValue(blob, "DeviceId"); id != "" {
		return id
	}
	return extractDsregcmdValue(blob, "WorkplaceDeviceId")
}

func runPowerShell(ctx context.Context, r runner, expr string) string {
	out, err := r.Run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", expr)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// runWmicValue reads a single property via `wmic` when PowerShell/CIM is unavailable.
func runWmicValue(ctx context.Context, r runner, alias, property string) string {
	out, err := r.Run(ctx, "wmic", alias, "get", property)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.EqualFold(line, property) {
			continue
		}
		return line
	}
	return ""
}

// extractDsregcmdValue parses `dsregcmd /status` output, which uses the format
//
//	  KeyName : Value
//
// for state fields. Returns the trimmed value for the first match.
func extractDsregcmdValue(blob, key string) string {
	scanner := bufio.NewScanner(strings.NewReader(blob))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(line[:colon]), key) {
			return strings.TrimSpace(line[colon+1:])
		}
	}
	return ""
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// isSentinelUUID reports known-bad or non-unique hardware UUID placeholders.
func isSentinelUUID(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	switch strings.ToUpper(value) {
	case "00000000-0000-0000-0000-000000000000",
		"FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF":
		return true
	}
	compact := strings.ReplaceAll(value, "-", "")
	if len(compact) == 0 {
		return false
	}
	first := strings.ToUpper(string(compact[0]))
	for _, c := range compact[1:] {
		if strings.ToUpper(string(c)) != first {
			return false
		}
	}
	return true
}

func sanitizeHardwareUUID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || isSentinelUUID(value) {
		return ""
	}
	return value
}
