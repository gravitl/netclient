package posture

import "testing"

const ioregSample = `
+-o IOPlatformExpertDevice  <class IOPlatformExpertDevice, id 0x100000201, registered, matched, active, busy 0 (5 ms), retain 38>
  {
    "IOPlatformSerialNumber" = "C02ABCDEFGHJ"
    "IOPlatformUUID" = "11111111-2222-3333-4444-555555555555"
    "compatible" = <"MacBookPro18,3">
  }
`

func TestCollectPlatformDarwin(t *testing.T) {
	r := fakeRunner{
		cmds: map[string]string{
			"ioreg -rd1 -c IOPlatformExpertDevice": ioregSample,
		},
	}
	var id DeviceIdentity
	collectPlatform(&id, r)
	if id.SerialNumber != "C02ABCDEFGHJ" {
		t.Errorf("SerialNumber = %q", id.SerialNumber)
	}
	if id.HardwareUUID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("HardwareUUID = %q", id.HardwareUUID)
	}
}

func TestExtractIORegValueMissing(t *testing.T) {
	if v := extractIORegValue("garbage", "IOPlatformUUID"); v != "" {
		t.Errorf("expected empty, got %q", v)
	}
}
