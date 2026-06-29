package posture

import "strings"

// dmiPlaceholders are common sysfs/DMI sentinel values that carry no device identity.
var dmiPlaceholders = map[string]struct{}{
	"not specified":            {},
	"to be filled by o.e.m.":   {},
	"default string":           {},
	"system serial number":     {},
	"none":                     {},
	"not applicable":           {},
	"n/a":                      {},
	"unknown":                  {},
	"o.e.m.":                   {},
	"fill by oem":              {},
	"0123456789":               {},
	"123456789":                {},
}

// sanitizeDMI wraps a probe and returns empty when the value is blank or a known placeholder.
func sanitizeDMI(p probe) probe {
	return func(r runner) string {
		v := strings.TrimSpace(p(r))
		if v == "" {
			return ""
		}
		if _, ok := dmiPlaceholders[strings.ToLower(v)]; ok {
			return ""
		}
		return v
	}
}

// collectPlatform fills Linux-specific identity fields. Linux hosts are not
// typically Entra-joined, so EntraDeviceID stays empty on Linux.
func collectPlatform(id *DeviceIdentity, r runner) {
	id.SerialNumber = firstNonEmpty(r,
		sanitizeDMI(readFile("/sys/class/dmi/id/product_serial")),
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
