package posture

import (
	"bufio"
	"strings"
)

// collectPlatform fills Windows-specific identity fields:
//   - SerialNumber / HardwareUUID via PowerShell Get-CimInstance, with registry
//     and wmic fallbacks that work when netclient runs as a SYSTEM service
//   - UserEmail / EntraDeviceID via `dsregcmd /status`, with registry
//     fallbacks for workplace-joined hosts (dsregcmd hides user join state
//     from services)
//
// EntraDeviceID prefers Azure AD join DeviceId; when the host is only
// workplace-joined, WorkplaceDeviceId (or its JoinInfo registry key) is used.
//
// Each probe is best-effort and leaves the field empty on failure.
func collectPlatform(id *DeviceIdentity, r runner) {
	id.SerialNumber = firstNonEmptyString(
		runPowerShell(r, "(Get-CimInstance Win32_BIOS).SerialNumber"),
		readLocalMachineStringValue(biosRegPath, "SystemSerialNumber"),
	)
	id.HardwareUUID = firstNonEmptyString(
		runPowerShell(r, "(Get-CimInstance Win32_ComputerSystemProduct).UUID"),
		runWmicValue(r, "csproduct", "uuid"),
		readLocalMachineStringValue(biosRegPath, "SystemProductGuid"),
	)

	entraID, userEmail := "", ""
	if out, err := r.Run("dsregcmd", "/status"); err == nil && out != "" {
		entraID = extractEntraDeviceID(out)
		userEmail = firstValidUserEmail(
			parseExecutingAccountName(extractDsregcmdValue(out, "Executing Account Name")),
			extractDsregcmdValue(out, "WorkAccount"),
			extractDsregcmdValue(out, "UserPrincipalName"),
		)
	}
	regDeviceID, regUserEmail := readJoinInfoFromRegistry()
	id.EntraDeviceID = firstNonEmptyString(entraID, regDeviceID)
	id.UserEmail = firstValidUserEmail(
		userEmail,
		regUserEmail,
		collectCloudDomainJoinUserEmail(r),
	)
}

// extractEntraDeviceID returns the Azure AD device object ID when present,
// otherwise the workplace-join device ID for work/school account enrollment.
func extractEntraDeviceID(blob string) string {
	if id := extractDsregcmdValue(blob, "DeviceId"); id != "" {
		return id
	}
	return extractDsregcmdValue(blob, "WorkplaceDeviceId")
}

func runPowerShell(r runner, expr string) string {
	out, err := r.Run("powershell", "-NoProfile", "-NonInteractive", "-Command", expr)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// runWmicValue reads a single property via `wmic` when PowerShell/CIM is unavailable.
func runWmicValue(r runner, alias, property string) string {
	out, err := r.Run("wmic", alias, "get", property)
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

// collectCloudDomainJoinUserEmail scans AAD join registry for a human UPN.
// dsregcmd run as SYSTEM often reports the machine account instead.
func collectCloudDomainJoinUserEmail(r runner) string {
	out := runPowerShell(r, `
$base = 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo'
if (-not (Test-Path $base)) { return }
foreach ($key in Get-ChildItem $base -ErrorAction SilentlyContinue) {
  $email = (Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue).UserEmail
  if ($email -and $email -like '*@*' -and $email -notlike '*$*') {
    $email
    return
  }
}
`)
	return strings.TrimSpace(out)
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
