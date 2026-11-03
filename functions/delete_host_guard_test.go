package functions

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestShouldIgnoreStaleDeleteHost(t *testing.T) {
	ignoreDeleteHostUntil.Store(0)
	t.Cleanup(func() { ignoreDeleteHostUntil.Store(0) })

	assert.False(t, ShouldIgnoreStaleDeleteHost())

	ArmIgnoreStaleDeleteHost()
	assert.True(t, ShouldIgnoreStaleDeleteHost())
	// Window stays armed until it expires (multiple MQ deliveries).
	assert.True(t, ShouldIgnoreStaleDeleteHost())

	ignoreDeleteHostUntil.Store(time.Now().Add(-time.Second).UnixNano())
	assert.False(t, ShouldIgnoreStaleDeleteHost())
}
