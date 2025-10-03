package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	netmakerResolverFileMarker = "# Managed by netmaker\n"
	searchDomainsResolverFile  = "domains.netmaker"
)

type darwinManager struct{}

func NewManager() (Manager, error) {
	return &darwinManager{}, nil
}

func (d *darwinManager) Configure(config Config) error {
	err := d.resetConfig()
	if err != nil {
		return err
	}

	if len(config.Nameservers) > 0 && len(config.SearchDomains) > 0 {
		domainResolverConf := new(bytes.Buffer)

		domainResolverConf.WriteString(netmakerResolverFileMarker)
		for _, nameserver := range config.Nameservers {
			domainResolverConf.WriteString(fmt.Sprintf("nameserver %s\n", nameserver.String()))
		}

		for _, domain := range config.SearchDomains {
			if domain != "." {
				resolverFilePath := filepath.Join("/etc/resolver", domain)
				err = os.WriteFile(resolverFilePath, domainResolverConf.Bytes(), 0644)
				if err != nil {
					return err
				}
			}
		}

		searchConf := new(bytes.Buffer)

		searchConf.WriteString(searchDomainsResolverFile)
		searchConf.WriteString(fmt.Sprintf("search %s\n", strings.Join(config.SearchDomains, " ")))

		return os.WriteFile(filepath.Join("/etc/resolver", searchDomainsResolverFile), searchConf.Bytes(), 0644)
	}

	return nil
}

func (d *darwinManager) resetConfig() error {
	resolverFiles, err := os.ReadDir("/etc/resolver")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, resolverFile := range resolverFiles {
		if !resolverFile.Type().IsRegular() {
			continue
		}

		resolverFilePath := filepath.Join("/etc/resolver", resolverFile.Name())
		contents, err := os.ReadFile(resolverFilePath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}

		if !strings.HasPrefix(string(contents), netmakerResolverFileMarker) {
			continue
		}

		err = os.Remove(resolverFilePath)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *darwinManager) SupportsInterfaceSpecificConfig() bool {
	return false
}
