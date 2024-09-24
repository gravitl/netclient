package dns

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"golang.org/x/exp/slog"
)

func isResolvectlSupported() bool {
	_, err := exec.LookPath("resolvectl")
	return err == nil
}

func SetupResolvconf() (err error) {

	if isResolvectlSupported() {
		err = setupResolvectl()
	} else {
		err = setupResolveconf()
	}

	return err
}

func RestoreResolvconf() (err error) {

	if isResolvectlSupported() {

	} else {
		err = releaseResolveconf()
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
	slog.Error("dnsIp", "debug", dnsIp)
	_, err = ncutils.RunCmd(fmt.Sprintf("resolvectl dns netmaker %s", dnsIp), false)
	if err != nil {
		slog.Error("add DNS IP for netmaker failed", "error", err.Error())
		return
	}

	domains := ""
	for _, v := range config.GetNodes() {
		domains = domains + " " + v.Network
	}
	slog.Error("domains", "debug", domains)
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

	return nil
}

func releaseResolveconf() error {

	return nil
}
