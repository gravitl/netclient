package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckDeviceNetworkApproval(t *testing.T) {
	orig := fetchDeviceNetworksImpl
	t.Cleanup(func() { fetchDeviceNetworksImpl = orig })

	fetchDeviceNetworksImpl = func(_, _ string) ([]DeviceNetwork, error) {
		return []DeviceNetwork{
			{NetworkID: "open-net", Status: "available"},
			{NetworkID: "pending-net", Status: "pending"},
			{NetworkID: "needs-approval", Status: "approval_required"},
			{NetworkID: "blocked-net", Status: "blocked"},
		}, nil
	}

	assert.NoError(t, checkDeviceNetworkApproval("open-net", "srv", "tok"))
	assert.ErrorIs(t, checkDeviceNetworkApproval("pending-net", "srv", "tok"), ErrApprovalPending)
	assert.ErrorIs(t, checkDeviceNetworkApproval("needs-approval", "srv", "tok"), ErrApprovalRequired)
	assert.ErrorIs(t, checkDeviceNetworkApproval("blocked-net", "srv", "tok"), ErrDeviceBlocked)
}

func TestCheckDeviceNetworkAccessPendingBlocksBeforeJIT(t *testing.T) {
	orig := fetchDeviceNetworksImpl
	t.Cleanup(func() { fetchDeviceNetworksImpl = orig })

	fetchDeviceNetworksImpl = func(_, _ string) ([]DeviceNetwork, error) {
		return []DeviceNetwork{
			{
				NetworkID:        "jit-pending-net",
				Status:           "pending",
				JITAppliesToUser: true,
				HasJITAccess:     false,
			},
		}, nil
	}

	err := checkDeviceNetworkAccess("jit-pending-net", "srv", "tok")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrApprovalPending)
}
