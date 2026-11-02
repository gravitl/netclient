//go:build !windows
// +build !windows

package local

// SetIPForwardingWindows is a no-op on non-Windows builds.
func SetIPForwardingWindows() error {
	return nil
}

// EnableForwardingOnInterfaces is a no-op on non-Windows builds.
func EnableForwardingOnInterfaces(aliases ...string) error {
	return nil
}

// DisableForwardingOnInterfaces is a no-op on non-Windows builds.
func DisableForwardingOnInterfaces(aliases ...string) error {
	return nil
}
