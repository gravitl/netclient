package wireguard

import (
	"net"
	"testing"

	"github.com/gravitl/netclient/config"
	"github.com/stretchr/testify/assert"
)

type fakePinRoutes struct {
	routes  map[string]string
	removed []string
}

func (f *fakePinRoutes) ops() underlayPinOps {
	return underlayPinOps{
		install: func(ip net.IP, via string) error {
			f.routes[ip.String()] = via
			return nil
		},
		remove: func(ip net.IP, _ string) {
			delete(f.routes, ip.String())
			f.removed = append(f.removed, ip.String())
		},
	}
}

func setupUnderlayPinTest(t *testing.T, pins []config.UnderlayPin) *fakePinRoutes {
	t.Helper()
	prev := config.Netclient()
	prevPersist := persistUnderlayPins
	prevArmed, prevKnown := underlayPinsArmed, underlayPinsArmKnown
	t.Cleanup(func() {
		if prev != nil {
			config.UpdateNetclient(*prev)
		}
		persistUnderlayPins = prevPersist
		underlayPinsArmed, underlayPinsArmKnown = prevArmed, prevKnown
	})
	persistUnderlayPins = func() {}
	nc := config.Config{UnderlayPins: pins}
	nc.CurrGwNmIP = net.ParseIP("100.64.0.1")
	config.UpdateNetclient(nc)
	underlayPinsArmKnown = false

	f := &fakePinRoutes{routes: map[string]string{}}
	for _, p := range pins {
		f.routes[p.IP] = p.Via
	}
	return f
}

func pinIPs(s ...string) []net.IP {
	out := make([]net.IP, 0, len(s))
	for _, v := range s {
		out = append(out, net.ParseIP(v))
	}
	return out
}

func recordedPins() map[string]string {
	out := map[string]string{}
	for _, p := range config.Netclient().UnderlayPins {
		out[p.IP] = p.Via
	}
	return out
}

func TestReconcileUnderlayPinsMovesPinsToNewGateway(t *testing.T) {
	f := setupUnderlayPinTest(t, []config.UnderlayPin{
		{IP: "198.51.100.1", Via: "192.168.1.1"},
		{IP: "198.51.100.2", Via: "192.168.1.1"},
	})

	reconcileUnderlayPins(false, pinIPs("198.51.100.1", "198.51.100.2"),
		viaGateway(net.ParseIP("10.0.0.1")), true, f.ops())

	want := map[string]string{"198.51.100.1": "10.0.0.1", "198.51.100.2": "10.0.0.1"}
	assert.Equal(t, want, f.routes, "pins must follow the new LAN gateway")
	assert.Equal(t, want, recordedPins())
}

func TestReconcileUnderlayPinsRemovesStalePins(t *testing.T) {
	f := setupUnderlayPinTest(t, []config.UnderlayPin{
		{IP: "198.51.100.1", Via: "192.168.1.1"},
		{IP: "198.51.100.9", Via: "192.168.1.1"},
		{IP: "2001:db8::9", Via: "fe80::1"},
	})

	reconcileUnderlayPins(false, pinIPs("198.51.100.1", "198.51.100.3"),
		viaGateway(net.ParseIP("192.168.1.1")), true, f.ops())

	assert.Equal(t, []string{"198.51.100.9"}, f.removed, "IPv6 pins belong to the other family pass")
	assert.Equal(t, map[string]string{
		"198.51.100.1": "192.168.1.1",
		"198.51.100.3": "192.168.1.1",
		"2001:db8::9":  "fe80::1",
	}, recordedPins())
}

func TestReconcileUnderlayPinsWithoutPruneKeepsAndMovesPins(t *testing.T) {
	f := setupUnderlayPinTest(t, []config.UnderlayPin{
		{IP: "198.51.100.1", Via: "192.168.1.1"},
	})

	reconcileUnderlayPins(false, nil, viaGateway(net.ParseIP("10.0.0.1")), false, f.ops())

	assert.Empty(t, f.removed)
	assert.Equal(t, map[string]string{"198.51.100.1": "10.0.0.1"}, recordedPins())
}

func TestRemoveUnderlayPinsDisarmsRefresh(t *testing.T) {
	f := setupUnderlayPinTest(t, []config.UnderlayPin{
		{IP: "198.51.100.1", Via: "192.168.1.1"},
		{IP: "2001:db8::1", Via: "fe80::1"},
	})

	removeUnderlayPins(false, f.ops())
	assert.Equal(t, []string{"198.51.100.1"}, f.removed)
	assert.Equal(t, map[string]string{"2001:db8::1": "fe80::1"}, recordedPins())

	// A monitor refresh racing teardown must not reinstall anything.
	reconcileUnderlayPins(false, pinIPs("198.51.100.1"), viaGateway(net.ParseIP("192.168.1.1")), true, f.ops())
	assert.NotContains(t, f.routes, "198.51.100.1")

	armUnderlayPins()
	reconcileUnderlayPins(false, pinIPs("198.51.100.1"), viaGateway(net.ParseIP("192.168.1.1")), true, f.ops())
	assert.Equal(t, "192.168.1.1", f.routes["198.51.100.1"])
}
