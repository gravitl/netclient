package posture

import "testing"

const dsregcmdSample = `
+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+

         AzureAdJoined : YES
      EnterpriseJoined : NO
          DomainJoined : NO
        Virtual Device : NO
            Device Name : DESKTOP-EXAMPLE

+----------------------------------------------------------------------+
| Device Details                                                       |
+----------------------------------------------------------------------+

              DeviceId : abcd1234-1111-2222-3333-444455556666
            Thumbprint : DEADBEEF
TenantName             : Contoso

+----------------------------------------------------------------------+
| User State                                                           |
+----------------------------------------------------------------------+

  Executing Account Name : Contoso\jane.doe
WorkAccount : jane.doe@contoso.com
`

func TestCollectPlatformWindowsParsesDsregcmd(t *testing.T) {
	r := fakeRunner{
		cmds: map[string]string{
			"powershell -NoProfile -NonInteractive -Command (Get-CimInstance Win32_BIOS).SerialNumber":              "ABC123",
			"powershell -NoProfile -NonInteractive -Command (Get-CimInstance Win32_ComputerSystemProduct).UUID":     "99999999-8888-7777-6666-555555555555",
			"dsregcmd /status": dsregcmdSample,
		},
	}
	var id DeviceIdentity
	collectPlatform(&id, r)
	if id.SerialNumber != "ABC123" {
		t.Errorf("SerialNumber = %q", id.SerialNumber)
	}
	if id.HardwareUUID != "99999999-8888-7777-6666-555555555555" {
		t.Errorf("HardwareUUID = %q", id.HardwareUUID)
	}
	if id.EntraDeviceID != "abcd1234-1111-2222-3333-444455556666" {
		t.Errorf("EntraDeviceID = %q", id.EntraDeviceID)
	}
	if id.UserEmail != "Contoso\\jane.doe" {
		t.Errorf("UserEmail = %q", id.UserEmail)
	}
}

func TestExtractDsregcmdValueCaseInsensitive(t *testing.T) {
	got := extractDsregcmdValue("deviceid : XYZ", "DeviceId")
	if got != "XYZ" {
		t.Errorf("got %q, want XYZ", got)
	}
}
