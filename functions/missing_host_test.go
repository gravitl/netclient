package functions

import (
	"errors"
	"testing"

	"github.com/gravitl/netclient/auth"
	"github.com/stretchr/testify/assert"
)

func TestIsMissingHostError(t *testing.T) {
	assert.True(t, auth.IsMissingHostError(errors.New("failed to authenticate 400 record not found")))
	assert.True(t, auth.IsMissingHostError(errors.New("Record Not Found")))
	assert.False(t, auth.IsMissingHostError(errors.New("failed to authenticate 401 unauthorized")))
	assert.False(t, auth.IsMissingHostError(nil))
}
