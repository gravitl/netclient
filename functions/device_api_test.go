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
