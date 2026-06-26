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

  Executing Account Name : Contoso\jane.doe, jane.doe@contoso.com
WorkAccount : jane.doe@contoso.com
`

func TestCollectPlatformWindowsParsesDsregcmd(t *testing.T) {
	r := fakeRunner{
		cmds: map[string]string{
			"powershell -NoProfile -NonInteractive -Command (Get-CimInstance Win32_BIOS).SerialNumber":          "ABC123",
			"powershell -NoProfile -NonInteractive -Command (Get-CimInstance Win32_ComputerSystemProduct).UUID": "99999999-8888-7777-6666-555555555555",
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
}

func TestExtractDsregcmdValueCaseInsensitive(t *testing.T) {
	got := extractDsregcmdValue("deviceid : XYZ", "DeviceId")
	if got != "XYZ" {
		t.Errorf("got %q, want XYZ", got)
	}
}

const dsregcmdWorkplaceSample = `
+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+

             AzureAdJoined : NO
          EnterpriseJoined : NO
              DomainJoined : NO
           WorkplaceJoined : YES

+----------------------------------------------------------------------+
| Work Account 1                                                       |
+----------------------------------------------------------------------+

         WorkplaceDeviceId : 53234f50-db3a-4f97-a2ec-08285902c1dc
       WorkplaceTenantId : 8362a4d3-912c-433b-acec-5118c90884e7
       WorkplaceTenantName : Default Directory
`

func TestCollectPlatformWindowsWorkplaceJoinFallback(t *testing.T) {
	r := fakeRunner{
		cmds: map[string]string{
			"powershell -NoProfile -NonInteractive -Command (Get-CimInstance Win32_BIOS).SerialNumber":          "",
			"powershell -NoProfile -NonInteractive -Command (Get-CimInstance Win32_ComputerSystemProduct).UUID": "",
			"wmic csproduct get uuid": "UUID\n\n53234f50-db3a-4f97-a2ec-08285902c1dc",
			"dsregcmd /status":        dsregcmdWorkplaceSample,
		},
	}
	var id DeviceIdentity
	collectPlatform(&id, r)
	if id.EntraDeviceID != "53234f50-db3a-4f97-a2ec-08285902c1dc" {
		t.Errorf("EntraDeviceID = %q, want workplace device id", id.EntraDeviceID)
	}
	if id.HardwareUUID != "53234f50-db3a-4f97-a2ec-08285902c1dc" {
		t.Errorf("HardwareUUID = %q", id.HardwareUUID)
	}
}

func TestExtractEntraDeviceIDPrefersAzureADJoin(t *testing.T) {
	blob := `
              DeviceId : aaaa-bbbb
         WorkplaceDeviceId : cccc-dddd
`
	if got := extractEntraDeviceID(blob); got != "aaaa-bbbb" {
		t.Errorf("got %q, want aaaa-bbbb", got)
	}
}

func TestLooksLikeGUID(t *testing.T) {
	if !looksLikeGUID("53234f50-db3a-4f97-a2ec-08285902c1dc") {
		t.Error("expected valid guid")
	}
	if looksLikeGUID("DEADBEEF") {
		t.Error("thumbprint should not match guid helper")
	}
}

func TestIsLoadedUserSID(t *testing.T) {
	if !isLoadedUserSID("S-1-5-21-3681983559-1923665867-785417408-1007") {
		t.Error("expected user sid")
	}
	if isLoadedUserSID("S-1-5-18") {
		t.Error("system sid should be skipped")
	}
	if isLoadedUserSID("S-1-5-21-3681983559-1923665867-785417408-1007_Classes") {
		t.Error("class sid should be skipped")
	}
}

func TestIsSentinelUUID(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"00000000-0000-0000-0000-000000000000", true},
		{"ffffffff-ffff-ffff-ffff-ffffffffffff", true},
		{"11111111-1111-1111-1111-111111111111", true},
		{"99999999-8888-7777-6666-555555555555", false},
		{"53234f50-db3a-4f97-a2ec-08285902c1dc", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isSentinelUUID(tc.value); got != tc.want {
			t.Errorf("isSentinelUUID(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestCollectPlatformWindowsSkipsSentinelHardwareUUID(t *testing.T) {
	r := fakeRunner{
		cmds: map[string]string{
			"powershell -NoProfile -NonInteractive -Command (Get-CimInstance Win32_BIOS).SerialNumber":          "ABC123",
			"powershell -NoProfile -NonInteractive -Command (Get-CimInstance Win32_ComputerSystemProduct).UUID": "00000000-0000-0000-0000-000000000000",
			"wmic csproduct get uuid": "UUID\n\n99999999-8888-7777-6666-555555555555",
		},
	}
	var id DeviceIdentity
	collectPlatform(&id, r)
	if id.HardwareUUID != "99999999-8888-7777-6666-555555555555" {
		t.Errorf("HardwareUUID = %q, want fallback after sentinel", id.HardwareUUID)
	}
}
