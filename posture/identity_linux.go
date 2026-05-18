package posture

// collectPlatform fills Linux-specific identity fields. Linux hosts are not
// typically Entra-joined, so UserEmail and EntraDeviceID stay empty.
func collectPlatform(id *DeviceIdentity, r runner) {
	id.SerialNumber = firstNonEmpty(r,
		readFile("/sys/class/dmi/id/product_serial"),
		readFile("/sys/class/dmi/id/board_serial"),
	)
	id.HardwareUUID = firstNonEmpty(r,
		readFile("/sys/class/dmi/id/product_uuid"),
		readFile("/etc/machine-id"),
		readFile("/var/lib/dbus/machine-id"),
	)
}

// readFile returns a probe that reads a single file via the injected runner.
func readFile(path string) probe {
	return func(r runner) string {
		v, err := r.ReadFile(path)
		if err != nil {
			return ""
		}
		return v
	}
}

type probe func(runner) string

func firstNonEmpty(r runner, probes ...probe) string {
	for _, p := range probes {
		if v := p(r); v != "" {
			return v
		}
	}
	return ""
}
