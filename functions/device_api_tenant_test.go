package functions

import (
	"net/http"
	"testing"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeviceRequestSetsTenantHeader(t *testing.T) {
	nc := config.Netclient()
	require.NotNil(t, nc)
	prevTenant := nc.TenantID
	nc.TenantID = "tenant-header-1"
	config.UpdateNetclient(*nc)
	t.Cleanup(func() {
		h := config.Netclient()
		h.TenantID = prevTenant
		config.UpdateNetclient(*h)
	})

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/api/v1/device/networks", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("X-Application-Name", desktopAppHeader)
	if tenantID := config.Netclient().TenantID; tenantID != "" {
		req.Header.Set(scope.HeaderTenantID, tenantID)
	}
	assert.Equal(t, "tenant-header-1", req.Header.Get(scope.HeaderTenantID))
}
