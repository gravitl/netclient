package functions

import (
	"testing"

	"github.com/matryer/is"
)

func TestIsVersionCompatible(t *testing.T) {
	is := is.New(t)
	t.Run("lower version", func(t *testing.T) {
		ok := IsVersionComptatible("v0.15.0")
		is.Equal(ok, false)
	})
	t.Run("equal version", func(t *testing.T) {
		ok := IsVersionComptatible("v0.18.0")
		is.Equal(ok, true)
	})
	t.Run("higher version", func(t *testing.T) {
		ok := IsVersionComptatible("v0.19.0")
		is.Equal(ok, true)
	})
}
