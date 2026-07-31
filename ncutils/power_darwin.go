package ncutils

// RegisterPowerEventHandlers is a no-op on Darwin. It exists so callers can
// register suspend/resume handlers without platform-specific build tags;
// only Windows currently delivers these events.
func RegisterPowerEventHandlers(suspend, resumeAutomatic, resumeSuspend func()) error {
	return nil
}

// UnregisterPowerEventHandlers is a no-op on Darwin.
func UnregisterPowerEventHandlers() {}
