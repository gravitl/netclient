package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/exp/slog"
)

const (
	resolvconfConfFile         = "/etc/resolvconf.conf"
	netmakerResolvconfConfDir  = "/etc/resolvconf.conf.d"
	netmakerResolvconfConfFile = "/etc/resolvconf.conf.d/netmaker.conf"
)

type openresolvManager struct {
	seedNameservers   []net.IP
	seedSearchDomains []string
}

func newOpenresolvManager(opts ...ManagerOption) (*openresolvManager, error) {
	o := &openresolvManager{}
	var options ManagerOptions
	for _, opt := range opts {
		opt(&options)
	}

	err := o.readSeedConfig()
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read /etc/resolv.conf: %v", err)
	}

	err = o.ensureResolvconfSource()
	if err != nil {
		return nil, fmt.Errorf("failed to ensure resolvconf sources netmaker config: %v", err)
	}

	if options.cleanupResidual {
		for _, iface := range options.residualInterfaces {
			err := o.resetConfig(iface)
			if err != nil {
				return nil, fmt.Errorf("failed to cleanup config for interface (%s): %v", iface, err)
			}
		}
	}

	return o, nil
}

func (o *openresolvManager) Configure(iface string, config Config) error {
	if iface == "" {
		return fmt.Errorf("interface name is required")
	}

	if config.Remove {
		return o.resetConfig(iface)
	}

	confBytes := new(bytes.Buffer)

	var cmd *exec.Cmd
	if config.SplitDNS {
		// config is split dns, we want to seed the original config into the new one.
		var nameservers []net.IP
		var searchDomains []string
		nameservers = append(nameservers, config.Nameservers...)
		nameservers = append(nameservers, o.seedNameservers...)
		nameservers = append(nameservers, net.ParseIP("8.8.8.8"), net.ParseIP("2001:4860:4860::8888"))
		searchDomains = append(searchDomains, config.SearchDomains...)
		searchDomains = append(searchDomains, o.seedSearchDomains...)

		writeConfig(confBytes, nameservers, searchDomains)
		cmd = exec.Command("resolvconf", "-m", "0", "-a", iface)
	} else {
		// config is full dns, we want this config to be exclusive.
		writeConfig(confBytes, config.Nameservers, config.SearchDomains)
		cmd = exec.Command("resolvconf", "-m", "0", "-x", "-a", iface)
	}
	cmd.Stdin = confBytes
	out, err := cmd.CombinedOutput()
	if err != nil {
		out := strings.TrimSpace(string(out))
		slog.Error(fmt.Sprintf("error configuring interface (%s) dns settings: %v: %s", iface, err, out))
		return fmt.Errorf("failed to configure interface (%s): %v", iface, err)
	}

	return nil
}

func (o *openresolvManager) resetConfig(iface string) error {
	out, err := exec.Command("resolvconf", "-d", iface).CombinedOutput()
	if err != nil {
		out := strings.TrimSpace(string(out))
		if strings.Contains(out, "No resolv.conf") ||
			strings.Contains(out, "Failed to resolve interface") ||
			strings.Contains(out, "No such device") {
			return nil
		}

		slog.Error(fmt.Sprintf("error resetting interface (%s) dns settings: %v: %s", iface, err, out))
		return err
	}

	return nil
}

func (o *openresolvManager) readSeedConfig() error {
	seedBytes, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return err
	}

	for _, line := range strings.Split(string(seedBytes), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "nameserver":
			for _, field := range fields[1:] {
				nameserver := net.ParseIP(field)
				if nameserver != nil {
					o.seedNameservers = append(o.seedNameservers, nameserver)
				}
			}
		case "search", "domain":
			o.seedSearchDomains = append(o.seedSearchDomains, fields[1:]...)
		}
	}

	return nil
}

func (o *openresolvManager) ensureResolvconfSource() error {
	err := os.MkdirAll(netmakerResolvconfConfDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create netmaker resolvconf config dir: %v", err)
	}

	content := "resolv_conf_local_only=NO\n"
	err = os.WriteFile(netmakerResolvconfConfFile, []byte(content), 0644)
	if err != nil {
		return fmt.Errorf("failed to write drop-in config: %v", err)
	}

	// Ensure global resolvconf conf sources our drop-in
	sysContent, err := os.ReadFile(resolvconfConfFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %v", resolvconfConfFile, err)
	}

	sourceNetmakerResolvconfConf := "[ -f " + netmakerResolvconfConfFile + " ] && . " + netmakerResolvconfConfFile
	if strings.Contains(string(sysContent), sourceNetmakerResolvconfConf) {
		return nil
	}

	f, err := os.OpenFile(resolvconfConfFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open %s: %v", resolvconfConfFile, err)
	}

	defer f.Close()

	_, err = fmt.Fprintf(f, "\n%s\n", sourceNetmakerResolvconfConf)
	return err
}
