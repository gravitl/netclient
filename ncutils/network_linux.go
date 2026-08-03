package ncutils

// RegisterNetworkChangeHandler is a no-op on Linux. It exists so callers can
// register a network-change handler without platform-specific build tags;
// only Windows currently delivers these events.
func RegisterNetworkChangeHandler(onChange func()) error {
	return nil
}

// UnregisterNetworkChangeHandler is a no-op on Linux.
func UnregisterNetworkChangeHandler() {}
