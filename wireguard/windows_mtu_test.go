package wireguard

import "testing"

func TestSetWindowsMTUUsesActiveWireGuard(t *testing.T) {
	tests := []struct {
		name          string
		mtu           int
		userspace     bool
		wantUserspace bool
		wantNT        bool
	}{
		{name: "WireGuardNT", mtu: 1280, wantNT: true},
		{name: "userspace", mtu: 1280, userspace: true, wantUserspace: true},
		{name: "no MTU", mtu: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotUserspace, gotNT bool
			setWindowsMTU(tt.mtu, tt.userspace,
				func() { gotUserspace = true },
				func() { gotNT = true })
			if gotUserspace != tt.wantUserspace || gotNT != tt.wantNT {
				t.Errorf("userspace setter called = %v, WireGuardNT setter called = %v; want %v, %v",
					gotUserspace, gotNT, tt.wantUserspace, tt.wantNT)
			}
		})
	}
}
