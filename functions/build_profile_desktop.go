//go:build desktop

package functions

const (
	// BuildProfile is the compile-time product flavor.
	BuildProfile = "desktop"
)

// IsDesktopBuild reports whether this binary was built with -tags desktop.
func IsDesktopBuild() bool { return true }
