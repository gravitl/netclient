package dns

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"golang.org/x/exp/slog"
)

var dnsConfigMutex = sync.Mutex{} // used to mutex functions of the DNS

const (
	resolvconfFilePath    = "/etc/resolv.conf"
	resolvconfFileBkpPath = "/etc/netclient/resolv.conf.nm.bkp"
	resolvUplinkPath      = "/etc/systemd/resolved.conf"
	resolvUplinkBkpPath   = "/etc/netclient/resolved.conf.nm.bkp"
	resolvconfUplinkPath  = "/run/systemd/resolve/resolv.conf"
)

func isStubSupported() bool {
	return config.Netclient().DNSManagerType == DNS_MANAGER_STUB
}

func isUplinkSupported() bool {
	return config.Netclient().DNSManagerType == DNS_MANAGER_UPLINK
}

func isResolveconfSupported() bool {
	return config.Netclient().DNSManagerType == DNS_MANAGER_RESOLVECONF
}

// func isFileSupported() bool {
// 	return config.Netclient().DNSManagerType == DNS_MANAGER_FILE
// }

// Flush local DNS cache
func FlushLocalDnsCache() (err error) {
	dnsConfigMutex.Lock()
	defer dnsConfigMutex.Unlock()
	if isStubSupported() || isUplinkSupported() {
		_, err = ncutils.RunCmd("resolvectl flush-caches", false)
		if err != nil {
			slog.Warn("Flush local DNS domain caches failed", "error", err.Error())
		}
	}
	return err
}

// Entry point to setup DNS settings
func SetupDNSConfig() (err error) {
	dnsConfigMutex.Lock()
	defer dnsConfigMutex.Unlock()
	if isStubSupported() {
		err = setupResolvectl()
	} else if isUplinkSupported() {
		err = setupResolveUplink()
	} else if isResolveconfSupported() {
	} else {
		err = setupResolveconf()
	}

	//write to dns.json
	syncDNSJsonFile()

	return err
}

// Entry point to restore DNS settings
func RestoreDNSConfig() (err error) {
	dnsConfigMutex.Lock()
	defer dnsConfigMutex.Unlock()
	if isStubSupported() {

	} else if isUplinkSupported() {
		err = restoreResolveUplink()
	} else if isResolveconfSupported() {
	} else {
		err = restoreResolveconf()
	}

	cleanDNSJsonFile()

	return err
}

func buildAddConfigContentUplink() ([]string, error) {

	dnsIp := GetDNSServerInstance().AddrStr
	if dnsIp == "" {
		return []string{}, errors.New("no listener is running")
	}

	dnsIp = getIpFromServerString(dnsIp)
	ns := "DNS=" + dnsIp

	f, err := os.Open(resolvUplinkPath)
	if err != nil {
		slog.Error("error opending file", "error", resolvUplinkPath, err.Error())
		return []string{}, err
	}
	defer f.Close()

	rawBytes, err := io.ReadAll(f)
	if err != nil {
		slog.Error("error reading file", "error", resolvUplinkPath, err.Error())
		return []string{}, err
	}
	lines := strings.Split(string(rawBytes), "\n")
	lNo := 21
	for i, line := range lines {
		if strings.HasPrefix(line, "#DNS=") {
			lNo = i
			break
		}
	}

	lines = slices.Insert(lines, lNo, ns)

	return lines, nil
}

func setupResolveUplink() (err error) {

	// backup /etc/systemd/resolved.conf
	err = backupResolveconfFile(resolvUplinkPath, resolvUplinkBkpPath)
	if err != nil {
		slog.Error("could not backup ", resolvUplinkPath, "error", err.Error())
		return err
	}

	// add nameserver
	lines, err := buildAddConfigContentUplink()
	if err != nil {
		slog.Error("could not build config content", "error", err.Error())
		return err
	}

	f, err := os.OpenFile(resolvUplinkPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
	if err != nil {
		slog.Error("error opending file", "error", resolvUplinkPath, err.Error())
		return err
	}
	defer f.Close()

	for _, v := range lines {
		if v != "" {
			_, err = fmt.Fprintln(f, v)
			if err != nil {
				slog.Error("error writing file", "error", resolvUplinkPath, err.Error())
				return err
			}
		}
	}

	_, err = ncutils.RunCmd("systemctl restart systemd-resolved", false)
	if err != nil {
		slog.Error("restart systemd-resolved failed", "error", err.Error())
		return err
	}

	return nil
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
		slog.Warn("add DNS IP for netmaker failed", "error", err.Error())
	}

	domains := ""
	defaultDomain := config.GetServer(config.CurrServer).DefaultDomain
	if defaultDomain != "" {
		domains = domains + " " + defaultDomain
	}

	_, err = ncutils.RunCmd(fmt.Sprintf("resolvectl domain netmaker %s", domains), false)
	if err != nil {
		slog.Warn("add DNS domain for netmaker failed", "error", err.Error())
	}

	time.Sleep(1 * time.Second)
	_, err = ncutils.RunCmd("resolvectl flush-caches", false)
	if err != nil {
		slog.Warn("Flush local DNS domain caches failed", "error", err.Error())
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

func backupResolveconfFile(src, dst string) error {

	_, err := os.Stat(dst)
	if err != nil {
		src_file, err := os.Open(src)
		if err != nil {
			slog.Error("could not open ", src, "error", err.Error())
			return err
		}
		defer src_file.Close()
		dst_file, err := os.Create(dst)
		if err != nil {
			slog.Error("could not open ", dst, "error", err.Error())
			return err
		}
		defer dst_file.Close()

		_, err = io.Copy(dst_file, src_file)
		if err != nil {
			slog.Error("could not backup ", src, "error", err.Error())
			return err
		}
	}
	return nil
}

func buildAddConfigContent() ([]string, error) {

	//get nameserver and search domain
	ns, domains, err := getNSAndDomains()
	if err != nil {
		slog.Error("error in getting getNSAndDomains", "error", err.Error())
		return []string{}, err
	}

	f, err := os.Open(resolvconfFilePath)
	if err != nil {
		slog.Error("error opending file", "error", resolvconfFilePath, err.Error())
		return []string{}, err
	}
	defer f.Close()

	rawBytes, err := io.ReadAll(f)
	if err != nil {
		slog.Error("error reading file", "error", resolvconfFilePath, err.Error())
		return []string{}, err
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

	return lines, nil
}

func setupResolveconf() error {

	// backup /etc/resolv.conf
	err := backupResolveconfFile(resolvconfFilePath, resolvconfFileBkpPath)
	if err != nil {
		slog.Error("could not backup ", resolvconfFilePath, "error", err.Error())
		return err
	}

	// add nameserver and search domain
	lines, err := buildAddConfigContent()
	if err != nil {
		slog.Error("could not build config content", "error", err.Error())
		return err
	}

	f, err := os.OpenFile(resolvconfFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
	if err != nil {
		slog.Error("error opending file", "error", resolvconfFilePath, err.Error())
		return err
	}
	defer f.Close()

	for _, v := range lines {
		if v != "" {
			_, err = fmt.Fprintln(f, v)
			if err != nil {
				slog.Error("error writing file", "error", resolvconfFilePath, err.Error())
				return err
			}
		}
	}

	return nil
}

func getNSAndDomains() (string, string, error) {

	dnsIp := GetDNSServerInstance().AddrStr
	if dnsIp == "" {
		return "", "", errors.New("no listener is running")
	}
	if len(config.GetNodes()) == 0 {
		return "", "", errors.New("no network joint")
	}

	domains := "search"
	defaultDomain := config.GetServer(config.CurrServer).DefaultDomain
	if defaultDomain != "" {
		domains = domains + " " + defaultDomain
	}
	if config.Netclient().DNSSearch != "" {
		domains = domains + " " + config.Netclient().DNSSearch
	} else {
		domains = domains + " ."
	}

	dnsIp = getIpFromServerString(dnsIp)

	ns := "nameserver"
	ns = ns + " " + dnsIp

	return ns, domains, nil
}

func getDomains() (string, error) {

	dnsConfig, err := readDNSJsonFile()
	if err != nil {
		return "", err
	}

	domains := "search"
	defaultDomain := dnsConfig.DefaultDomain
	if defaultDomain != "" {
		domains = domains + " " + defaultDomain
	}
	dnsSearch := dnsConfig.DNSSearch
	if dnsSearch != "" {
		domains = domains + " " + dnsSearch
	}

	return domains, nil
}

func buildDeleteConfigContentUplink() ([]string, error) {

	//get nameserver
	dnsIp := GetDNSServerInstance().AddrStr
	if dnsIp == "" {
		return []string{}, errors.New("no listener is running")
	}

	f, err := os.Open(resolvUplinkPath)
	if err != nil {
		slog.Error("error opending file", "error", resolvUplinkPath, err.Error())
		return []string{}, err
	}
	defer f.Close()

	rawBytes, err := io.ReadAll(f)
	if err != nil {
		slog.Error("error reading file", "error", resolvUplinkPath, err.Error())
		return []string{}, err
	}
	lines := strings.Split(string(rawBytes), "\n")

	dnsIp = getIpFromServerString(dnsIp)
	ns := "DNS=" + dnsIp

	lNo := 21
	for i, line := range lines {
		if strings.Contains(line, ns) {
			lNo = i
			break
		}
	}

	lines = slices.Delete(lines, lNo, lNo+1)

	return lines, nil
}

func buildDeleteConfigContent() ([]string, error) {
	f, err := os.Open(resolvconfFilePath)
	if err != nil {
		slog.Error("error opending file", "error", resolvconfFilePath, err.Error())
		return []string{}, err
	}
	defer f.Close()

	rawBytes, err := io.ReadAll(f)
	if err != nil {
		slog.Error("error reading file", "error", resolvconfFilePath, err.Error())
		return []string{}, err
	}
	lines := strings.Split(string(rawBytes), "\n")

	//get search domain
	domains, err := getDomains()
	if err != nil {
		slog.Warn("error in getting getDomains", "error", err.Error())
		return []string{}, err
	}

	lNo := 100
	for i, line := range lines {
		if strings.Contains(line, domains) {
			lNo = i
			break
		}
	}

	lines = slices.Delete(lines, lNo, lNo+1)
	lines = slices.Delete(lines, lNo, lNo+1)

	return lines, nil
}

func restoreResolveUplink() error {

	lines, err := buildDeleteConfigContentUplink()
	if err != nil {
		slog.Warn("could not build config content", "error", err.Error())
		return err
	}

	err = writeConfigUplink(lines)
	if err != nil {
		slog.Warn("could not write config content", "error", err.Error())
		return err
	}
	time.Sleep(1 * time.Second)

	_, err = ncutils.RunCmd("systemctl restart systemd-resolved", false)
	if err != nil {
		slog.Warn("restart systemd-resolved failed", "error", err.Error())
		//remove the nameserver from file directly
		removeNSUplink()
		return err
	}

	return nil
}

func writeConfigUplink(lines []string) error {

	f, err := os.OpenFile(resolvUplinkPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
	if err != nil {
		slog.Error("error opending file", "error", resolvUplinkPath, err.Error())
		return err
	}
	defer f.Close()

	for _, v := range lines {
		if v != "" {
			_, err = fmt.Fprintln(f, v)
			if err != nil {
				slog.Error("error writing file", "error", resolvUplinkPath, err.Error())
				return err
			}
		}
	}
	return nil
}

func buildDeleteConfigUplink() ([]string, error) {
	//get nameserver
	dnsIp := GetDNSServerInstance().AddrStr
	if dnsIp == "" {
		return []string{}, errors.New("no listener is running")
	}

	f, err := os.Open(resolvconfFilePath)
	if err != nil {
		slog.Error("error opending file", "error", resolvconfFilePath, err.Error())
		return []string{}, err
	}
	defer f.Close()

	rawBytes, err := io.ReadAll(f)
	if err != nil {
		slog.Error("error reading file", "error", resolvconfFilePath, err.Error())
		return []string{}, err
	}
	lines := strings.Split(string(rawBytes), "\n")

	//get search domain
	dnsIp = getIpFromServerString(dnsIp)
	ns := "nameserver " + dnsIp

	lNo := 100
	for i, line := range lines {
		if strings.Contains(line, ns) {
			lNo = i
			break
		}
	}

	lines = slices.Delete(lines, lNo, lNo+1)

	return lines, nil
}

func removeNSUplink() error {
	lines, err := buildDeleteConfigUplink()
	if err != nil {
		slog.Warn("could not build config content", "error", err.Error())
		return err
	}

	f, err := os.OpenFile(resolvconfUplinkPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
	if err != nil {
		slog.Error("error opending file", "error", resolvconfUplinkPath, err.Error())
		return err
	}
	defer f.Close()

	for _, v := range lines {
		if v != "" {
			_, err = fmt.Fprintln(f, v)
			if err != nil {
				slog.Error("error writing file", "error", resolvconfUplinkPath, err.Error())
				return err
			}
		}
	}

	return nil

}

func restoreResolveconf() error {

	lines, err := buildDeleteConfigContent()
	if err != nil {
		slog.Warn("could not build config content", "error", err.Error())
		return err
	}

	f, err := os.OpenFile(resolvconfFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
	if err != nil {
		slog.Error("error opending file", "error", resolvconfFilePath, err.Error())
		return err
	}
	defer f.Close()

	for _, v := range lines {
		if v != "" {
			_, err = fmt.Fprintln(f, v)
			if err != nil {
				slog.Error("error writing file", "error", resolvconfFilePath, err.Error())
				return err
			}
		}
	}

	return nil
}

// Entry point to read current DNS settings and write to config
func InitDNSConfig() {
	dnsConfigMutex.Lock()
	defer dnsConfigMutex.Unlock()
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
			} else if strings.Contains(line, "generated by resolvconf(8)") {
				config.Netclient().DNSManagerType = DNS_MANAGER_RESOLVECONF
			} else {
				config.Netclient().DNSManagerType = DNS_MANAGER_FILE
			}
			continue
			//for ubuntu 20
		} else if i == 3 {
			if strings.Contains(line, "DNS stub resolver") {
				config.Netclient().DNSManagerType = DNS_MANAGER_STUB
			}
			continue
		} else {
			if strings.HasPrefix(line, "nameserver") {
				ns := strings.TrimSpace(line[11:])
				if ns != "127.0.0.53" && ns != "127.0.0.54" {
					nslist = append(nslist, ns)
				}
			}
			if strings.HasPrefix(line, "search") {
				config.Netclient().DNSSearch = strings.TrimSpace(line[7:])
			}
			if strings.HasPrefix(line, "options") {
				config.Netclient().DNSOptions = strings.TrimSpace(line[8:])
			}
		}
	}

	//For stub and uplink mode, 127.0.0.53 is contained in resolve.conf file, this is to get the real upstream dns servers
	if len(nslist) == 0 && config.Netclient().DNSManagerType != DNS_MANAGER_FILE {
		output, err := ncutils.RunCmd("resolvectl status", false)
		if err != nil {
			slog.Error("resolvectl status command failed", "error", err.Error())
		} else {
			lines := strings.Split(output, "\n")

			for _, l := range lines {
				if strings.HasPrefix(strings.TrimSpace(l), "DNS Servers:") {

					t := strings.TrimSpace(strings.TrimSpace(l)[12:])
					ll := strings.Split(t, " ")
					if len(ll) > 0 {
						nslist = append(nslist, ll...)
					}

					break
				}
			}
		}
	}

	//in case there is no upstream name server found, add Google's DNS server as upstream DNS servers
	if len(nslist) == 0 {
		nslist = append(nslist, "8.8.8.8")
		nslist = append(nslist, "8.8.4.4")
		nslist = append(nslist, "2001:4860:4860::8888")
		nslist = append(nslist, "2001:4860:4860::8844")
	}

	config.Netclient().NameServers = nslist
}
