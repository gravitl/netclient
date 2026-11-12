package wireguard

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Creates a real WireGuardNT adapter, so it needs administrator rights and
// wireguard.dll; opt in with NETCLIENT_WGNT_TEST=1.
func TestSetMTUAppliesToWireGuardNTAdapter(t *testing.T) {
	if os.Getenv("NETCLIENT_WGNT_TEST") != "1" {
		t.Skip("set NETCLIENT_WGNT_TEST=1 to run, needs administrator and wireguard.dll")
	}
	// Differs from the WireGuardNT default of 1420, so a no-op SetMTU fails.
	const mtu = 1280
	nc := &NCIface{Name: "nctest-wgnt-mtu", MTU: mtu, IsTestIface: true}
	if err := nc.Create(); err != nil {
		t.Fatalf("create adapter: %v", err)
	}
	t.Cleanup(nc.Close)
	if UserspaceWGActive() {
		t.Fatal("userspace WireGuard is active; this test covers the WireGuardNT path")
	}

	if err := nc.SetMTU(); err != nil {
		t.Fatalf("SetMTU: %v", err)
	}

	luid := nc.Iface.(*driver.Adapter).LUID()
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		row, err := luid.IPInterface(family)
		if err != nil {
			t.Fatalf("read IP interface, family %d: %v", family, err)
		}
		if row.NLMTU != mtu {
			t.Errorf("family %d NlMtu = %d, want %d", family, row.NLMTU, mtu)
		}
	}
}
