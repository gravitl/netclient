// Package posture collects stable MDM device identifiers and queries the
// server-side posture status endpoint. Netclient itself does NOT evaluate
// device compliance (disk encryption, AV, firewall, patch level,
// jailbreak/root, screen lock) - that responsibility stays in the MDM and
// is enforced by the netmaker server.
package posture

import (
	"context"
	"os"
	"runtime"
)

// DeviceIdentity is the platform identifier set collected locally and copied
// onto schema.Host fields via ApplyIdentity during join and check-in.
type DeviceIdentity struct {
	Hostname      string `json:"hostname"`
	SerialNumber  string `json:"serial_number"`
	HardwareUUID  string `json:"hardware_uuid"`
	OS            string `json:"os"`
	EntraDeviceID string `json:"entra_device_id"`
}

// runner abstracts external-command execution so platform collectors can be
// unit-tested without shelling out.
type runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
	ReadFile(path string) (string, error)
}

// defaultRunner is overridden in tests.
var defaultRunner runner = osRunner{}

// Collect gathers the device identity for the current host. It never returns
// an error: any per-field failure leaves that field empty.
func Collect() DeviceIdentity {
	id := DeviceIdentity{OS: runtime.GOOS}
	if name, err := os.Hostname(); err == nil {
		id.Hostname = name
	}
	collectPlatform(&id, defaultRunner)
	return id
}
