// Package daemon provide functions to control execution of deamons
package daemon

// Install - Calls the correct function to install the netclient as a daemon service on the given operating system.
func Install() error {
	return install()
}

// Restart - restarts a system daemon
func Restart() error {
	return restart()
}

// Start - starts system daemon using signals (unix) or init system (windows)
func Start() error {
	return start()
}

// HardRestart - restarts system daemon using init system
func HardRestart() error {
	return hardRestart()
}

// Stop - stops a system daemon
func Stop() error {
	return stop()
}

func CleanUp() error {
	return cleanUp()
}
