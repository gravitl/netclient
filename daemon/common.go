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

// Start - starts system daemon
func Start() error {
	return start()
}

// Stop - stops a system daemon
func Stop() error {
	return stop()
}

// CleanUp - calls the private cleanup func of every OS rather than just putting CleanUp in every OS
func CleanUp() error {
	return cleanUp()
}
