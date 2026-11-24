//go:build desktop

package local

// IsDesktopBuild reports whether this binary was built with -tags desktop.
func IsDesktopBuild() bool { return true }
