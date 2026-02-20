//go:build !windows

package adcompat

// IsDomainJoined always returns false on non-Windows platforms.
func IsDomainJoined() bool { return false }

// IsDomainController always returns false on non-Windows platforms.
func IsDomainController() bool { return false }

// GetDomainSuffixes always returns nil on non-Windows platforms.
func GetDomainSuffixes() []string { return nil }

// ShouldEnableADCompat always returns false on non-Windows platforms.
func ShouldEnableADCompat(_ ADCompatMode) (enabled bool, isDC bool) { return false, false }
