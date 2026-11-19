package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsVersionCompatible(t *testing.T) {
	t.Run("lower version", func(t *testing.T) {
		assert.False(t, IsVersionComptatible("v0.15.0"))
	})
	t.Run("equal version", func(t *testing.T) {
		assert.True(t, IsVersionComptatible("v0.18.0"))
	})
	t.Run("higher version", func(t *testing.T) {
		assert.True(t, IsVersionComptatible("v0.19.0"))
	})
}

func TestVersionLessThan(t *testing.T) {
	t.Run("lower version", func(t *testing.T) {
		ok, err := versionLessThan("v0.15.0", "v0.16.0")
		require.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("equal version", func(t *testing.T) {
		ok, err := versionLessThan("v0.18.0", "v0.18.0")
		require.NoError(t, err)
		assert.False(t, ok)
	})
	t.Run("higher version", func(t *testing.T) {
		ok, err := versionLessThan("v0.19.0", "v0.18.0")
		require.NoError(t, err)
		assert.False(t, ok)
	})
}

func TestVersionUnknown(t *testing.T) {
	t.Run("no semver 1", func(t *testing.T) {
		ok, err := versionLessThan("not-sem-ver", "v0.16.0")
		assert.False(t, ok)
		assert.Error(t, err)
	})
	t.Run("no semver 2", func(t *testing.T) {
		ok, err := versionLessThan("v0.16.0", "not-sem-ver")
		assert.False(t, ok)
		assert.Error(t, err)
	})
}
