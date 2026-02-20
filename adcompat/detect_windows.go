//go:build windows

package adcompat

import (
	"os/exec"
	"strings"

	"golang.org/x/exp/slog"
)

// IsDomainJoined returns true if the machine is joined to an Active Directory domain.
func IsDomainJoined() bool {
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
		"(Get-CimInstance Win32_ComputerSystem).PartOfDomain")
	out, err := cmd.Output()
	if err != nil {
		slog.Warn("failed to detect domain membership", "error", err)
		return false
	}
	return strings.TrimSpace(string(out)) == "True"
}

// IsDomainController returns true if the machine is running as a domain controller (NTDS service present and running).
func IsDomainController() bool {
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
		"(Get-Service NTDS -ErrorAction SilentlyContinue).Status")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "Running"
}

// GetDomainSuffixes returns the DNS suffixes associated with the AD domain, including the primary
// domain suffix and any configured suffix search list entries.
func GetDomainSuffixes() []string {
	var suffixes []string
	seen := make(map[string]bool)

	// Primary domain suffix
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
		"(Get-WmiObject Win32_ComputerSystem).Domain")
	out, err := cmd.Output()
	if err == nil {
		domain := strings.TrimSpace(string(out))
		if domain != "" {
			lower := strings.ToLower(domain)
			suffixes = append(suffixes, lower)
			seen[lower] = true
		}
	}

	// Global DNS suffix search list
	cmd = exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
		"(Get-DnsClientGlobalSetting).SuffixSearchList -join ','")
	out, err = cmd.Output()
	if err == nil {
		for _, s := range strings.Split(strings.TrimSpace(string(out)), ",") {
			s = strings.TrimSpace(strings.ToLower(s))
			if s != "" && !seen[s] {
				suffixes = append(suffixes, s)
				seen[s] = true
			}
		}
	}

	return suffixes
}

// ShouldEnableADCompat determines whether AD compatibility mode should be active and whether
// this machine is a domain controller.
func ShouldEnableADCompat(mode ADCompatMode) (enabled bool, isDC bool) {
	switch mode {
	case ADCompatDisabled:
		return false, false
	case ADCompatEnabled:
		isDC = IsDomainController()
		return true, isDC
	default: // ADCompatAuto
		if !IsDomainJoined() {
			return false, false
		}
		isDC = IsDomainController()
		return true, isDC
	}
}
