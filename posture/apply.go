package posture

import "github.com/gravitl/netmaker/schema"

// ApplyIdentity copies MDM device-matching identifiers onto the host when
// identity reporting is enabled. Fields are best-effort: empty strings are
// left unchanged when Collect() cannot determine a value.
func ApplyIdentity(host *schema.Host) {
	if host == nil {
		return
	}
	id := Collect()
	if id.EntraDeviceID != "" {
		host.EntraDeviceID = id.EntraDeviceID
	}
	if id.SerialNumber != "" {
		host.SerialNumber = id.SerialNumber
	}
	if id.HardwareUUID != "" {
		host.HardwareUUID = id.HardwareUUID
	}
	if id.UserEmail != "" {
		host.UserEmail = id.UserEmail
	}
}
