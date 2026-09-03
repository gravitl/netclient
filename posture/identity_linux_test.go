package posture

import "testing"

func TestCollectPlatformLinuxPrefersProductSerial(t *testing.T) {
	r := fakeRunner{
		files: map[string]string{
			"/sys/class/dmi/id/product_serial": "SN-PRIMARY",
			"/sys/class/dmi/id/board_serial":   "SN-FALLBACK",
			"/sys/class/dmi/id/product_uuid":   "uuid-primary",
			"/etc/machine-id":                  "machineid-fallback",
		},
	}
	var id DeviceIdentity
	collectPlatform(&id, r)
	if id.SerialNumber != "SN-PRIMARY" {
		t.Errorf("SerialNumber = %q, want SN-PRIMARY", id.SerialNumber)
	}
	if id.HardwareUUID != "uuid-primary" {
		t.Errorf("HardwareUUID = %q, want uuid-primary", id.HardwareUUID)
	}
	if id.EntraDeviceID != "" {
		t.Error("Linux should not populate EntraDeviceID")
	}
}

func TestCollectPlatformLinuxFallsBackToMachineID(t *testing.T) {
	r := fakeRunner{
		files: map[string]string{
			"/sys/class/dmi/id/board_serial": "SN-FALLBACK",
			"/etc/machine-id":                "machineid-fallback",
		},
	}
	var id DeviceIdentity
	collectPlatform(&id, r)
	if id.SerialNumber != "SN-FALLBACK" {
		t.Errorf("SerialNumber = %q, want SN-FALLBACK", id.SerialNumber)
	}
	if id.HardwareUUID != "machineid-fallback" {
		t.Errorf("HardwareUUID = %q, want machineid-fallback", id.HardwareUUID)
	}
}

func TestCollectPlatformLinuxAllMissing(t *testing.T) {
	var id DeviceIdentity
	collectPlatform(&id, fakeRunner{})
	if id.SerialNumber != "" || id.HardwareUUID != "" {
		t.Errorf("expected empty fields, got %+v", id)
	}
}

func TestCollectPlatformLinuxSkipsDMIPlaceholderSerial(t *testing.T) {
	r := fakeRunner{
		files: map[string]string{
			"/sys/class/dmi/id/product_serial": "  To Be Filled By O.E.M.  \n",
			"/sys/class/dmi/id/board_serial":     "SN-BOARD",
		},
	}
	var id DeviceIdentity
	collectPlatform(&id, r)
	if id.SerialNumber != "SN-BOARD" {
		t.Errorf("SerialNumber = %q, want SN-BOARD", id.SerialNumber)
	}
}

func TestSanitizeDMI(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"Not Specified", ""},
		{"default string", ""},
		{"  SN-REAL  ", "SN-REAL"},
		{"i-0abc123def456789", "i-0abc123def456789"},
	}
	for _, tc := range tests {
		got := sanitizeDMI(func(runner) string { return tc.in })(fakeRunner{})
		if got != tc.want {
			t.Errorf("sanitizeDMI(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
