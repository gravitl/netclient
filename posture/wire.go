package posture

import "os"

// IdentityReportingEnabled returns true when netclient should attach a
// device_identity sidecar to outbound host payloads (register POST, host
// update PUT, MQTT host update publish, SSO register message).
//
// Reporting is OFF by default because the matching netmaker server-side
// schema may not be deployed yet. Operators opt in by setting
//
//	NETCLIENT_MDM_POSTURE=1
//
// (also accepts "true", "yes", "on"). When the netmaker schema field
// is rolled out broadly, the default can flip to true.
func IdentityReportingEnabled() bool {
	switch os.Getenv("NETCLIENT_MDM_POSTURE") {
	case "1", "true", "TRUE", "True", "yes", "on":
		return true
	}
	return false
}
