package posture

import (
	"bufio"
	"strings"
)

// collectPlatform fills macOS-specific identity fields by parsing
// `ioreg -rd1 -c IOPlatformExpertDevice`. UserEmail and EntraDeviceID are
// left empty: macOS Entra/Intune enrollment is not exposed via a stable CLI
// hook; the MDM agent reports those upstream.
func collectPlatform(id *DeviceIdentity, r runner) {
	out, err := r.Run("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if err != nil || out == "" {
		return
	}
	id.SerialNumber = extractIORegValue(out, "IOPlatformSerialNumber")
	id.HardwareUUID = extractIORegValue(out, "IOPlatformUUID")
}

// extractIORegValue pulls the quoted value for a named property from
// `ioreg -rd1` output, e.g.:
//
//	"IOPlatformSerialNumber" = "C02ABCDEFGHJ"
func extractIORegValue(blob, key string) string {
	scanner := bufio.NewScanner(strings.NewReader(blob))
	needle := "\"" + key + "\""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.Contains(line, needle) {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		rhs := strings.TrimSpace(line[eq+1:])
		rhs = strings.Trim(rhs, "\"")
		return rhs
	}
	return ""
}
