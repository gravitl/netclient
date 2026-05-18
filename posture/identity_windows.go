package posture

import (
	"bufio"
	"strings"
)

// collectPlatform fills Windows-specific identity fields:
//   - SerialNumber / HardwareUUID via PowerShell Get-CimInstance
//   - UserEmail / EntraDeviceID via `dsregcmd /status`
//
// Each probe is best-effort and leaves the field empty on failure.
func collectPlatform(id *DeviceIdentity, r runner) {
	id.SerialNumber = runPowerShell(r,
		"(Get-CimInstance Win32_BIOS).SerialNumber")
	id.HardwareUUID = runPowerShell(r,
		"(Get-CimInstance Win32_ComputerSystemProduct).UUID")

	if out, err := r.Run("dsregcmd", "/status"); err == nil && out != "" {
		id.EntraDeviceID = extractDsregcmdValue(out, "DeviceId")
		id.UserEmail = firstNonEmptyString(
			extractDsregcmdValue(out, "Executing Account Name"),
			extractDsregcmdValue(out, "WorkAccount"),
			extractDsregcmdValue(out, "UserPrincipalName"),
		)
	}
}

func runPowerShell(r runner, expr string) string {
	out, err := r.Run("powershell", "-NoProfile", "-NonInteractive", "-Command", expr)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
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
