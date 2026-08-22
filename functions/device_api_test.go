package functions

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeDeviceNetworksWrappedResponse(t *testing.T) {
	body := []byte(`{
		"Code": 200,
		"Message": "fetched device networks",
		"Response": [{
			"network_id": "netmaker",
			"display_name": "netmaker",
			"joined": false,
			"connected": false,
			"pending": false,
			"status": "available",
			"approval_required": false,
			"jit_enabled": false,
			"jit_applies_to_user": false,
			"has_jit_access": true,
			"jit_pending_request": false
		}]
	}`)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
	var networks []DeviceNetwork
	err := decodeDeviceResponse(resp, &networks)
	require.NoError(t, err)
	require.Len(t, networks, 1)
	assert.Equal(t, "netmaker", networks[0].NetworkID)
	assert.Equal(t, "available", networks[0].Status)
}

func TestDecodeDeviceRegisterResponseWrappedHost(t *testing.T) {
	hostID := uuid.New()
	inner, err := json.Marshal(deviceRegisterPayload{
		Host: schema.Host{ID: hostID, Name: "test-host"},
	})
	require.NoError(t, err)
	body, err := json.Marshal(deviceSuccessResponse{
		Code:     200,
		Message:  "ok",
		Response: inner,
	})
	require.NoError(t, err)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
	registerResponse, err := decodeDeviceRegisterResponse(resp)
	require.NoError(t, err)
	assert.Equal(t, hostID, registerResponse.RequestedHost.ID)
	assert.Equal(t, "test-host", registerResponse.RequestedHost.Name)
}

func TestEnsureRegisterServerConfFillsMissingFields(t *testing.T) {
	resp := models.RegisterResponse{
		ServerConf: models.ServerConfig{
			API:    "api.example.com",
			Broker: "broker.example.com",
			Server: "internal-name",
		},
	}
	err := ensureRegisterServerConf(&resp, "api.example.com", "token")
	require.NoError(t, err)
	assert.Equal(t, "api.example.com", resp.ServerConf.Server)
	assert.Equal(t, "api.example.com", resp.ServerConf.API)
}
