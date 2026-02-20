//go:build !windows

package wireguard

// SetADCompatMetrics is a no-op on non-Windows platforms.
func SetADCompatMetrics(_ string) {}
