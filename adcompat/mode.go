package adcompat

import "strings"

// ADCompatMode represents the Windows AD compatibility mode setting.
type ADCompatMode int

const (
	ADCompatAuto     ADCompatMode = iota // detect and enable automatically
	ADCompatEnabled                      // force AD compatibility mode on
	ADCompatDisabled                     // legacy DNS override behavior
)

// ParseMode converts a string configuration value into an ADCompatMode.
// An empty string is treated as "auto".
func ParseMode(s string) ADCompatMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "enabled":
		return ADCompatEnabled
	case "disabled":
		return ADCompatDisabled
	default:
		return ADCompatAuto
	}
}
