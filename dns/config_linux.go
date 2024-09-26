package dns

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"golang.org/x/exp/slog"
)

const (
	resolvconfFilePath    = "/etc/resolv.conf"
	resolvconfFileBkpPath = "/etc/netclient/resolv.conf.nm.bkp"
)

func isStubSupported() bool {
	return config.Netclient().DNSManagerType == DNS_MANAGER_STUB
}

// func isUplinkSupported() bool {
// 	return config.Netclient().DNSManagerType == DNS_MANAGER_UPLINK
// }

// func isFileSupported() bool {
// 	return config.Netclient().DNSManagerType == DNS_MANAGER_FILE
// }

func SetupDNSConfig() (err error) {

	if isStubSupported() {
		err = setupResolvectl()
	} else {
		err = setupResolveconf()
	}

	return err
}

func RestoreDNSConfig() (err error) {

	if isStubSupported() {

	} else {
		err = restoreResolveconf()
	}

	return err
}

func setupResolvectl() (err error) {

	dnsIp := GetDNSServerInstance().AddrStr
	if dnsIp == "" {
		return errors.New("no listener is running")
	}
	if len(config.GetNodes()) == 0 {
		return errors.New("no network joint")
	}

	dnsIp = getIpFromServerString(dnsIp)

	_, err = ncutils.RunCmd(fmt.Sprintf("resolvectl dns netmaker %s", dnsIp), false)
	if err != nil {
		slog.Error("add DNS IP for netmaker failed", "error", err.Error())
		return
	}

	domains := ""
	for _, v := range config.GetNodes() {
		domains = domains + " " + v.Network
	}

	_, err = ncutils.RunCmd(fmt.Sprintf("resolvectl domain netmaker %s", domains), false)
	if err != nil {
		slog.Error("add DNS domain for netmaker failed", "error", err.Error())
		return
	}

	return nil
}

func getIpFromServerString(addrStr string) string {
	s := ""
	s = addrStr[0:strings.LastIndex(addrStr, ":")]

	if strings.Contains(s, "[") {
		s = strings.ReplaceAll(s, "[", "")
	}

	if strings.Contains(s, "]") {
		s = strings.ReplaceAll(s, "]", "")
	}

	return s
}

func setupResolveconf() error {

	// backup /etc/resolv.conf
	_, err := os.Stat(resolvconfFileBkpPath)
	if err != nil {
		src_file, err := os.Open(resolvconfFilePath)
		if err != nil {
			slog.Error("could not open ", resolvconfFilePath, "error", err.Error())
			return err
		}
		defer src_file.Close()
		dst_file, err := os.Create(resolvconfFileBkpPath)
		if err != nil {
			slog.Error("could not open ", resolvconfFileBkpPath, "error", err.Error())
			return err
		}
		defer dst_file.Close()

		_, err = io.Copy(dst_file, src_file)
		if err != nil {
			slog.Error("could not backup ", resolvconfFilePath, "error", err.Error())
			return err
		}
	}

	//get nameserver and search domain
	dnsIp := GetDNSServerInstance().AddrStr
	if dnsIp == "" {
		return errors.New("no listener is running")
	}
	if len(config.GetNodes()) == 0 {
		return errors.New("no network joint")
	}

	domains := "search"
	for _, v := range config.GetNodes() {
		domains = domains + " " + v.Network
	}
	domains = domains + " " + config.Netclient().DNSSearch

	dnsIp = getIpFromServerString(dnsIp)

	ns := "nameserver"
	ns = ns + " " + dnsIp

	// add nameserver and search domain
	f, err := os.Open(resolvconfFilePath)
	if err != nil {
		slog.Error("error opending file", "error", resolvconfFilePath, err.Error())
		return err
	}
	defer f.Close()

	rawBytes, err := io.ReadAll(f)
	if err != nil {
		slog.Error("error reading file", "error", resolvconfFilePath, err.Error())
		return err
	}
	lines := strings.Split(string(rawBytes), "\n")
	lNo := 0
	for i, line := range lines {
		if strings.HasPrefix(line, "nameserver") {
			lNo = i
			break
		}
	}

	lines = slices.Insert(lines, lNo, ns)
	lines = slices.Insert(lines, lNo, domains)

	f, err = os.OpenFile(resolvconfFilePath, os.O_CREATE|os.O_WRONLY, 0700)
	if err != nil {
		slog.Error("error opending file", "error", resolvconfFilePath, err.Error())
		return err
	}
	defer f.Close()

	for _, v := range lines {
		_, err = fmt.Fprintln(f, v)
		if err != nil {
			slog.Error("error writing file", "error", resolvconfFilePath, err.Error())
			return err
		}
	}

	return nil
}

func restoreResolveconf() error {

	f, err := os.Open(resolvconfFilePath)
	if err != nil {
		slog.Error("error opending file", "error", resolvconfFilePath, err.Error())
		return err
	}
	defer f.Close()

	rawBytes, err := io.ReadAll(f)
	if err != nil {
		slog.Error("error reading file", "error", resolvconfFilePath, err.Error())
		return err
	}
	lines := strings.Split(string(rawBytes), "\n")
	lNo := 0
	for i, line := range lines {
		if strings.HasPrefix(line, "nameserver") {
			lNo = i
			break
		}
	}

	//Delete the added search and nameserver two lines
	lines = slices.Delete(lines, lNo-1, lNo)

	f, err = os.OpenFile(resolvconfFilePath, os.O_CREATE|os.O_WRONLY, 0700)
	if err != nil {
		slog.Error("error opending file", "error", resolvconfFilePath, err.Error())
		return err
	}
	defer f.Close()

	for _, v := range lines {
		_, err = fmt.Fprintln(f, v)
		if err != nil {
			slog.Error("error writing file", "error", resolvconfFilePath, err.Error())
			return err
		}
	}

	//delete backup resolv.conf file
	err = os.Remove(resolvconfFileBkpPath)
	if err != nil {
		slog.Error("error writing file", "error", resolvconfFilePath, err.Error())
		return err
	}

	return nil
}

func InitDNSConfig() {

	f, err := os.Open(resolvconfFilePath)
	if err != nil {
		slog.Error("error opending file", "error", resolvconfFilePath, err.Error())
		return
	}
	defer f.Close()

	rawBytes, err := io.ReadAll(f)
	if err != nil {
		slog.Error("error reading file", "error", resolvconfFilePath, err.Error())
		return
	}
	lines := strings.Split(string(rawBytes), "\n")
	nslist := []string{}
	for i, line := range lines {
		if i == 0 {
			if strings.Contains(line, "/run/systemd/resolve/stub-resolv.conf") {
				config.Netclient().DNSManagerType = DNS_MANAGER_STUB
			} else if strings.Contains(line, "/run/systemd/resolve/resolv.conf") {
				config.Netclient().DNSManagerType = DNS_MANAGER_UPLINK
			} else {
				config.Netclient().DNSManagerType = DNS_MANAGER_FILE
			}
			continue
		} else {
			if strings.HasPrefix(line, "nameserver") {
				nslist = append(nslist, strings.TrimSpace(line[11:]))
			}
			if strings.HasPrefix(line, "search") {
				config.Netclient().DNSSearch = strings.TrimSpace(line[7:])
			}
			if strings.HasPrefix(line, "options") {
				config.Netclient().DNSOptions = strings.TrimSpace(line[8:])
			}
		}
	}

	config.Netclient().NameServers = nslist
}
