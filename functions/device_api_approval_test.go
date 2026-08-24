package functions

import (
	"testing"

	"github.com/gravitl/netmaker/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckDeviceNetworkAccess(t *testing.T) {
	orig := fetchDeviceNetworksImpl
	t.Cleanup(func() { fetchDeviceNetworksImpl = orig })

	fetchDeviceNetworksImpl = func(_, _ string) ([]models.DeviceNetwork, error) {
		return []models.DeviceNetwork{
			{NetworkID: "open-net", Status: "available"},
			{NetworkID: "blocked-net", Status: "blocked"},
			{
				NetworkID:        "jit-net",
				Status:           "available",
				JITAppliesToUser: true,
				HasJITAccess:     false,
			},
		}, nil
	}

	assert.NoError(t, checkDeviceNetworkAccess("open-net", "srv", "tok"))
	assert.ErrorIs(t, checkDeviceNetworkAccess("blocked-net", "srv", "tok"), ErrDeviceBlocked)
	assert.ErrorIs(t, checkDeviceNetworkAccess("jit-net", "srv", "tok"), ErrJITAccessRequired)
}

func TestCheckDeviceNetworkAccessJITRequiredStatus(t *testing.T) {
	orig := fetchDeviceNetworksImpl
	t.Cleanup(func() { fetchDeviceNetworksImpl = orig })

	fetchDeviceNetworksImpl = func(_, _ string) ([]models.DeviceNetwork, error) {
		return []models.DeviceNetwork{
			{NetworkID: "jit-required-net", Status: "jit_required"},
		}, nil
	}

	err := checkDeviceNetworkAccess("jit-required-net", "srv", "tok")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrJITAccessRequired)
}
