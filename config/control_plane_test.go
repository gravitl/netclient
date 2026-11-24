package config

import (
	"net"
	"testing"

	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsControlPlaneHostname(t *testing.T) {
	prevServer := CurrServer
	t.Cleanup(func() {
		SetLookupControlPlaneIPsForTest(nil)
		CurrServer = prevServer
		replaceControlPlaneByHost(map[string][]net.IP{})
		DeleteServer("cp-host-test")
	})

	SetLookupControlPlaneIPsForTest(func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.10")}, nil
	})
	CurrServer = "cp-host-test"
	UpdateServerConfig(&models.ServerConfig{
		Server: "cp-host-test",
		API:    "api.example.com:443",
		Broker: "broker.example.com:8883",
	})
	require.True(t, RefreshControlPlaneEndpoints(GetServer("cp-host-test")))

	assert.True(t, IsControlPlaneHostname("api.example.com"))
	assert.True(t, IsControlPlaneHostname("api.example.com."))
	assert.True(t, IsControlPlaneHostname("broker.example.com"))
	assert.False(t, IsControlPlaneHostname("google.com"))
}

func TestRefreshControlPlaneEndpointsKeepsCacheOnResolveFailure(t *testing.T) {
	prevServer := CurrServer
	t.Cleanup(func() {
		SetLookupControlPlaneIPsForTest(nil)
		CurrServer = prevServer
		replaceControlPlaneByHost(map[string][]net.IP{})
		DeleteServer("cp-keep-test")
	})

	SetLookupControlPlaneIPsForTest(func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("198.51.100.20")}, nil
	})
	CurrServer = "cp-keep-test"
	UpdateServerConfig(&models.ServerConfig{
		Server: "cp-keep-test",
		API:    "api.keep.test:443",
		Broker: "broker.keep.test:8883",
	})
	server := GetServer("cp-keep-test")
	require.NotNil(t, server)
	require.True(t, RefreshControlPlaneEndpoints(server))
	assert.Equal(t, "198.51.100.20", ControlPlaneIPsForHost("api.keep.test")[0].String())

	SetLookupControlPlaneIPsForTest(func(host string) ([]net.IP, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host}
	})
	assert.False(t, RefreshControlPlaneEndpoints(server))
	assert.Equal(t, "198.51.100.20", ControlPlaneIPsForHost("api.keep.test")[0].String())
	pinStrs := make([]string, 0, len(ControlPlanePinIPs()))
	for _, ip := range ControlPlanePinIPs() {
		pinStrs = append(pinStrs, ip.String())
	}
	assert.Contains(t, pinStrs, "198.51.100.20")
}
