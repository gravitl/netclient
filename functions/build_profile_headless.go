//go:build !desktop

package functions

const (
	// BuildProfile is the compile-time product flavor.
	BuildProfile = "headless"
)

// IsDesktopBuild reports whether this binary was built with -tags desktop.
func IsDesktopBuild() bool { return false }
