//go:build !linux && !darwin && !windows

package posture

// collectPlatform is a no-op stub for unsupported OSes; the cross-platform
// hostname + GOOS fields are still populated by Collect().
func collectPlatform(_ *DeviceIdentity, _ runner) {}
