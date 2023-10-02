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

func TestVersionLessThan(t *testing.T) {
	is := is.New(t)
	t.Run("lower version", func(t *testing.T) {
		ok, _ := versionLessThan("v0.15.0", "v0.16.0")
		is.Equal(ok, true)
	})
	t.Run("equal version", func(t *testing.T) {
		ok, _ := versionLessThan("v0.18.0", "v0.18.0")
		is.Equal(ok, false)
	})
	t.Run("higher version", func(t *testing.T) {
		ok, _ := versionLessThan("v0.19.0", "v0.18.0")
		is.Equal(ok, false)
	})
}

func TestVersionUnknown(t *testing.T) {
	is := is.New(t)
	t.Run("no semver 1", func(t *testing.T) {
		ok, err := versionLessThan("not-sem-ver", "v0.16.0")
		is.Equal(ok, false)
		if err == nil {
			t.Fatalf("error should be non-nil")
		}
	})
	t.Run("no semver 2", func(t *testing.T) {
		ok, err := versionLessThan("v0.16.0", "not-sem-ver")
		is.Equal(ok, false)
		if err == nil {
			t.Fatalf("error should be non-nil")
		}
	})
}
