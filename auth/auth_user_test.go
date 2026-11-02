package auth

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/gravitl/netclient/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticate_userOwnedRequiresSession(t *testing.T) {
	t.Cleanup(func() {
		UserTokenProvider = nil
		SetPendingUserToken("")
		CleanJwtToken()
	})

	host := &config.Config{}
	host.ID = uuid.New()
	host.OwnerUsername = "alice"

	UserTokenProvider = nil
	_, err := Authenticate(nil, host)
	require.ErrorIs(t, err, ErrUserSessionRequired)

	UserTokenProvider = func() string { return "user-jwt" }
	tok, err := Authenticate(nil, host)
	require.NoError(t, err)
	assert.Equal(t, "user-jwt", tok)
}

func TestAuthenticate_pendingUserTokenDuringLogin(t *testing.T) {
	t.Cleanup(func() {
		UserTokenProvider = nil
		SetPendingUserToken("")
		CleanJwtToken()
	})

	host := &config.Config{}
	host.ID = uuid.New()
	host.OwnerUsername = "alice"
	UserTokenProvider = nil

	SetPendingUserToken("pending-jwt")
	tok, err := Authenticate(nil, host)
	require.NoError(t, err)
	assert.Equal(t, "pending-jwt", tok)
}

func TestApplyAPIHeaders_setsHostID(t *testing.T) {
	host := &config.Config{}
	host.ID = uuid.New()
	headers := make(http.Header)
	ApplyAPIHeaders(headers, "tok", host)
	assert.Equal(t, "Bearer tok", headers.Get("Authorization"))
	assert.Equal(t, host.ID.String(), headers.Get(DeviceHostIDHeader))
}
