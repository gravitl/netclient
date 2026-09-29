//go:build !windows

package daemon

// MigrateWindowsService is a no-op outside Windows.
func MigrateWindowsService() bool { return false }
