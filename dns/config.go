package dns

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/gravitl/netclient/config"
	"golang.org/x/exp/slog"
)

const (
	DNS_MANAGER_STUB   = "stub"   // '/run/systemd/resolve/stub-resolv.conf'
	DNS_MANAGER_UPLINK = "uplink" // '/run/systemd/resolve/resolv.conf'
	DNS_MANAGER_FILE   = "file"   // other than above
)

var (
	dnsConfigPath = config.GetNetclientPath() + "dns.json"
)

type DNSConfig struct {
	Domains       []string `json:"domains"`
	DefaultDomain string   `json:"default_domain"`
	DNSSearch     string   `json:"dns_search"`
}

var dnsJsonMutex = sync.Mutex{}

// sync up DNS related config to dns.json
func syncDNSJsonFile() error {
	dnsJsonMutex.Lock()
	defer dnsJsonMutex.Unlock()

	//if dns.json existed, delete it at first
	_, err := os.Stat(dnsConfigPath)
	if err == nil {
		err = os.Remove(dnsConfigPath)
		if err != nil {
			slog.Error("error deleting file", "error", dnsConfigPath, err.Error())
		}
	}

	// read from config and build DNSConfig
	dnsConfig := &DNSConfig{}
	if config.Netclient().DNSSearch != "" {
		dnsConfig.DNSSearch = config.Netclient().DNSSearch + " ."
	} else {
		dnsConfig.DNSSearch = "."
	}

	defaultDomain := config.GetServer(config.CurrServer).DefaultDomain
	if defaultDomain != "" {
		dnsConfig.DefaultDomain = defaultDomain
	}

	domains := []string{}
	for _, v := range config.GetNodes() {
		domains = append(domains, v.Network)
	}
	dnsConfig.Domains = domains

	//write the DNSconfig to dns.json
	f, err := os.OpenFile(dnsConfigPath, os.O_CREATE|os.O_WRONLY, 0700)
	if err != nil {
		slog.Error("error opening file", "error", dnsConfigPath, err.Error())
		return err
	}
	defer f.Close()

	j := json.NewEncoder(f)
	j.SetIndent("", "    ")
	err = j.Encode(dnsConfig)
	if err != nil {
		slog.Error("error encoding file", "error", dnsConfigPath, err.Error())
		return err
	}

	return nil
}

// read dns.json file to DNSConfig object
func readDNSJsonFile() (dnsConfig DNSConfig, err error) {
	dnsJsonMutex.Lock()
	defer dnsJsonMutex.Unlock()

	if _, err := os.Stat(dnsConfigPath); err != nil {
		if os.IsNotExist(err) {
			slog.Error("file is not existed", "error", dnsConfigPath, err.Error())
			return DNSConfig{}, err
		}
	}

	f, err := os.Open(dnsConfigPath)
	if err != nil {
		slog.Error("error opening file", "error", dnsConfigPath, err.Error())
		return DNSConfig{}, err
	}
	defer f.Close()
	if err = json.NewDecoder(f).Decode(&dnsConfig); err != nil {
		slog.Error("error decoding file", "error", dnsConfigPath, err.Error())
		return DNSConfig{}, err
	}

	return dnsConfig, nil
}

// Clean up the dns.json file
func cleanDNSJsonFile() error {
	dnsJsonMutex.Lock()
	defer dnsJsonMutex.Unlock()
	//delete dns.json file
	err := os.Remove(dnsConfigPath)
	if err != nil {
		slog.Error("error removing file", "error", dnsConfigPath, err.Error())
		return err
	}

	return nil
}
