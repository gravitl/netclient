package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"golang.org/x/exp/slog"
)

const (
	resolvedConfDir  = "/etc/systemd/resolved.conf.d"
	resolvedConfFile = "/etc/systemd/resolved.conf.d/0-netmaker.conf"
)

type systemdStubManager struct{}

func newSystemdStubManager(opts ...ManagerOption) (*systemdStubManager, error) {
	s := &systemdStubManager{}
	var options ManagerOptions
	for _, opt := range opts {
		opt(&options)
	}

	if options.cleanupResidual {
		for _, iface := range options.residualInterfaces {
			err := s.resetConfig(iface)
			if err != nil {
				return nil, fmt.Errorf("failed to cleanup config for interface (%s): %v", iface, err)
			}
		}
	}

	return s, nil
}

func (s *systemdStubManager) Configure(iface string, config Config) error {
	if iface == "" {
		return fmt.Errorf("interface name is required")
	}

	if config.Remove {
		err := s.resetConfig(iface)
		if err != nil {
			return err
		}
	} else {
		nameservers := make([]string, len(config.Nameservers))
		for i, ip := range config.Nameservers {
			nameservers[i] = ip.String()
		}

		domainsMap := make(map[string]bool)
		for _, domain := range config.MatchDomains {
			domainsMap["~"+domain] = true
		}

		for _, domain := range config.SearchDomains {
			_, ok := domainsMap["~"+domain]
			if ok {
				delete(domainsMap, "~"+domain)
			}

			domainsMap[domain] = true
		}

		i := 0
		domains := make([]string, len(domainsMap))
		for domain := range domainsMap {
			domains[i] = domain
			i++
		}

		if !config.SplitDNS {
			domains = append(domains, "~.")
		}

		args := []string{"dns", iface}
		args = append(args, nameservers...)
		out, err := exec.Command("resolvectl", args...).CombinedOutput()
		if err != nil {
			out := strings.TrimSpace(string(out))
			slog.Error(fmt.Sprintf("error configuring interface (%s) dns nameserver settings: %v: %s", iface, err, out))
			return err
		}

		args = []string{"domain", iface}
		args = append(args, domains...)
		out, err = exec.Command("resolvectl", args...).CombinedOutput()
		if err != nil {
			out := strings.TrimSpace(string(out))
			slog.Error(fmt.Sprintf("error configuring interface (%s) dns domain settings: %v: %s", iface, err, out))
			return err
		}

		defaultRoute := "yes"
		if config.SplitDNS {
			defaultRoute = "no"
		}

		out, err = exec.Command("resolvectl", "default-route", iface, defaultRoute).CombinedOutput()
		if err != nil {
			out := strings.TrimSpace(string(out))
			slog.Error(fmt.Sprintf("error configuring interface (%s) dns default-route settings: %v: %s", iface, err, out))
			return err
		}
	}

	// resolvectl applies live; never restart systemd-resolved here — a failed
	// systemctl restart takes down the stub resolver and breaks all lookups.
	flushResolvedCaches()
	return nil
}

func (s *systemdStubManager) resetConfig(iface string) error {
	_, err := net.InterfaceByName(iface)
	if err != nil {
		var opErr *net.OpError
		if errors.As(err, &opErr) && strings.Contains(opErr.Err.Error(), "no such network interface") {
			return nil
		}
	}

	out, err := exec.Command("resolvectl", "dns", iface, "").CombinedOutput()
	if err != nil {
		out := strings.TrimSpace(string(out))
		if isInterfaceNotFoundError(out) {
			return nil
		}

		slog.Error(fmt.Sprintf("error resetting interface (%s) dns nameserver settings: %v: %s", iface, err, out))
		return err
	}

	out, err = exec.Command("resolvectl", "domain", iface, "").CombinedOutput()
	if err != nil {
		out := strings.TrimSpace(string(out))
		if isInterfaceNotFoundError(out) {
			return nil
		}

		slog.Error(fmt.Sprintf("error resetting interface (%s) dns domain settings: %v: %s", iface, err, out))
		return err
	}

	flushResolvedCaches()
	return nil
}

func isInterfaceNotFoundError(output string) bool {
	out := strings.TrimSpace(strings.ToLower(output))
	return strings.Contains(out, "no such device") ||
		strings.Contains(out, "no such link") ||
		strings.Contains(out, "does not exist") ||
		strings.Contains(out, "unknown interface")
}

// flushResolvedCaches best-effort clears the resolver cache. Failures are
// logged only — nameserver settings from resolvectl are already live.
func flushResolvedCaches() {
	out, err := exec.Command("resolvectl", "flush-caches").CombinedOutput()
	if err != nil {
		slog.Warn(fmt.Sprintf("resolvectl flush-caches failed: %v: %s", err, strings.TrimSpace(string(out))))
	}
}

// reloadResolvedDropins reloads systemd-resolved so resolved.conf.d changes
// take effect, without a hard restart that can leave the unit failed and
// break host DNS. Soft failures are logged; we still try to keep the unit up.
func reloadResolvedDropins() {
	out, err := exec.Command("systemctl", "reload", "systemd-resolved.service").CombinedOutput()
	if err == nil {
		flushResolvedCaches()
		return
	}
	slog.Warn(fmt.Sprintf("systemd-resolved reload failed, trying reload-or-restart: %v: %s",
		err, strings.TrimSpace(string(out))))

	out, err = exec.Command("systemctl", "reload-or-restart", "systemd-resolved.service").CombinedOutput()
	if err != nil {
		slog.Warn(fmt.Sprintf("systemd-resolved reload-or-restart failed: %v: %s",
			err, strings.TrimSpace(string(out))))
		// A failed restart can leave the unit inactive — recover resolution.
		if startOut, startErr := exec.Command("systemctl", "start", "systemd-resolved.service").CombinedOutput(); startErr != nil {
			slog.Error(fmt.Sprintf("systemd-resolved start after failed reload failed: %v: %s",
				startErr, strings.TrimSpace(string(startOut))))
		}
		return
	}
	flushResolvedCaches()
}

type systemdUplinkManager struct {
	configs map[string]Config
	mu      sync.Mutex
}

func newSystemdUplinkManager(opts ...ManagerOption) (*systemdUplinkManager, error) {
	s := &systemdUplinkManager{
		configs: make(map[string]Config),
	}
	var options ManagerOptions
	for _, opt := range opts {
		opt(&options)
	}

	err := os.MkdirAll(resolvedConfDir, 0755)
	if err != nil {
		return nil, err
	}

	if options.cleanupResidual {
		err := s.resetConfig()
		if err != nil {
			return nil, err
		}
	}

	return s, nil
}

func (s *systemdUplinkManager) Configure(iface string, config Config) error {
	if iface == "" {
		return fmt.Errorf("interface name is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if config.Remove {
		delete(s.configs, iface)
	} else {
		s.configs[iface] = config
	}

	var nameservers []string
	var domains []string
	nameserversMap := make(map[string]bool)
	domainsMap := make(map[string]bool)
	for _, config := range s.configs {
		for _, nameserver := range config.Nameservers {
			_, ok := nameserversMap[nameserver.String()]
			if !ok {
				nameserversMap[nameserver.String()] = true
				nameservers = append(nameservers, nameserver.String())
			}
		}

		for _, domain := range config.MatchDomains {
			_, ok := domainsMap["~"+domain]
			if !ok {
				domainsMap["~"+domain] = true
				domains = append(domains, "~"+domain)
			}
		}

		for _, domain := range config.SearchDomains {
			_, ok := domainsMap[domain]
			if !ok {
				domainsMap[domain] = true
				domains = append(domains, domain)
			}
		}

		if !config.SplitDNS {
			_, ok := domainsMap["~."]
			if !ok {
				domainsMap["~."] = true
				domains = append(domains, "~.")
			}
		}
	}

	err := s.writeConfig(nameservers, domains)
	if err != nil {
		return err
	}

	reloadResolvedDropins()
	return nil
}

func (s *systemdUplinkManager) resetConfig() error {
	err := os.Remove(resolvedConfFile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	reloadResolvedDropins()
	return nil
}

func (s *systemdUplinkManager) writeConfig(nameservers []string, domains []string) error {
	var buf bytes.Buffer

	buf.WriteString("[Resolve]\n")
	buf.WriteString("DNS=" + strings.Join(nameservers, " ") + "\n")
	buf.WriteString("Domains=" + strings.Join(domains, " ") + "\n")

	return os.WriteFile(resolvedConfFile, buf.Bytes(), 0644)
}
