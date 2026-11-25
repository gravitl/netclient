// The test needs root with CAP_SYS_ADMIN and CAP_NET_ADMIN plus the wireguard kernel module,
// so it skips on the CI runner. Run it with
// sudo go test ./functions/ -run TestLeaveNetworkKeepsOtherNetworksEgressRoutes -v.
package functions

import (
	"errors"
	"net"
	"os"
	"runtime"
	"testing"

	"github.com/google/uuid"
	"github.com/gravitl/netclient/cache"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TestLeaveNetworkKeepsOtherNetworksEgressRoutes puts the host into net1 and net2 on a real
// kernel WireGuard interface in a private namespace, gives both networks an egress route and
// checks that leaving net2 as the daemon keeps net1's route but drops net2's.
func TestLeaveNetworkKeepsOtherNetworksEgressRoutes(t *testing.T) {
	enterPrivateNetNamespace(t)
	isolateConfigDir(t)
	host := config.Netclient()
	prevID, prevKey, prevPort, prevMTU := host.ID, host.PrivateKey, host.ListenPort, host.MTU
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	testID := uuid.New()
	host.ID, host.PrivateKey = testID, key
	host.ListenPort, host.MTU = config.DefaultListenPort, config.DefaultMTU
	t.Cleanup(func() {
		host.ID, host.PrivateKey = prevID, prevKey
		host.ListenPort, host.MTU = prevPort, prevMTU
		cache.EgressRouteCache.Delete(testID.String())
		wireguard.SetEgressRoutesInCache(nil)
	})
	for network, address := range map[string]string{"net1": "198.51.100.2/24", "net2": "203.0.113.2/24"} {
		ip, ipnet, err := net.ParseCIDR(address)
		require.NoError(t, err)
		config.UpdateNodeMap(network, config.Node{CommonNode: models.CommonNode{
			ID: uuid.New(), HostID: host.ID, Network: network, NetworkRange: *ipnet,
			Address: net.IPNet{IP: ip, Mask: ipnet.Mask}, Connected: true,
		}})
	}
	t.Cleanup(func() {
		config.DeleteNode("net1")
		config.DeleteNode("net2")
	})
	nc := wireguard.NewNCIface(host, config.GetNodes())
	require.NoError(t, nc.Create())
	require.NoError(t, nc.Configure())

	const net1Range, net2Range = "192.0.2.0/24", "100.64.0.0/24"
	net1, net2 := config.GetNode("net1"), config.GetNode("net2")
	// Same cache a peer update fills from the server; SetRoutesFromCache is what the rebuild reads.
	wireguard.SetEgressRoutesInCache([]models.EgressNetworkRoutes{
		{EgressGwAddr: net.IPNet{IP: net.ParseIP("198.51.100.1"), Mask: net1.NetworkRange.Mask}, NodeAddr: net1.Address,
			EgressRangesWithMetric: []models.EgressRangeMetric{{Network: net1Range}}, Network: "net1"},
		{EgressGwAddr: net.IPNet{IP: net.ParseIP("203.0.113.1"), Mask: net2.NetworkRange.Mask}, NodeAddr: net2.Address,
			EgressRangesWithMetric: []models.EgressRangeMetric{{Network: net2Range}}, Network: "net2"},
	})
	wireguard.SetRoutesFromCache()
	require.True(t, hasEgressRoute(t, net1Range), "egress route %s of net1 was not installed before leaving", net1Range)
	require.True(t, hasEgressRoute(t, net2Range), "egress route %s of net2 was not installed before leaving", net2Range)

	if _, err := LeaveNetwork("net2", true); err != nil {
		t.Logf("LeaveNetwork: %v", err)
	}
	assert.True(t, hasEgressRoute(t, net1Range), "egress route %s of net1 is gone from the netmaker interface after leaving net2", net1Range)
	assert.False(t, hasEgressRoute(t, net2Range), "egress route %s of net2 is still on the netmaker interface after leaving net2", net2Range)
}

// hasEgressRoute reports whether the netmaker interface carries a route to cidr.
func hasEgressRoute(t *testing.T, cidr string) bool {
	t.Helper()
	link, err := netlink.LinkByName("netmaker")
	require.NoError(t, err)
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	require.NoError(t, err)
	for _, route := range routes {
		if route.Dst != nil && route.Dst.String() == cidr {
			return true
		}
	}
	return false
}

// enterPrivateNetNamespace moves the test goroutine onto a locked thread in a fresh network
// namespace. The thread is never unlocked, so it exits with the test and the namespaces go
// with it.
func enterPrivateNetNamespace(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNET | unix.CLONE_NEWNS); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skip("needs CAP_SYS_ADMIN to create a network namespace")
		}
		t.Fatal(err)
	}
	// A shared root would carry mounts made below into the host namespace.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
}

// isolateConfigDir mounts a tmpfs over the config directory on the private mount namespace,
// so LeaveNetwork's config writes never reach the host's own netclient install.
func isolateConfigDir(t *testing.T) {
	t.Helper()
	dir := config.GetNetclientPath()
	_, statErr := os.Stat(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	require.NoError(t, unix.Mount("tmpfs", dir, "tmpfs", 0, ""))
	t.Cleanup(func() {
		_ = unix.Unmount(dir, 0)
		if errors.Is(statErr, os.ErrNotExist) {
			_ = os.Remove(dir)
		}
	})
}
