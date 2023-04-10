package routes

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
)

var (
	errCantParse = fmt.Errorf("can't parse")
	errNoGateway = fmt.Errorf("no gateway")
)

type windowsCmdRoute struct {
	Iface string
	GW    string
}

func getWindowsGateway() (ip net.IP, err error) {
	cmd := exec.Command("route", "print", "0.0.0.0")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	return getIPFromOutputWindows(output)
}

func getIPFromOutputWindows(output []byte) (net.IP, error) {
	parsedOutput, err := parse(output)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(parsedOutput.GW)
	if ip == nil {
		return nil, errCantParse
	}
	return ip, nil
}

func parse(output []byte) (windowsCmdRoute, error) {
	lines := strings.Split(string(output), "\n")
	sep := 0
	for idx, line := range lines {
		if sep == 3 {
			if len(lines) <= idx+2 {
				return windowsCmdRoute{}, errNoGateway
			}

			fields := strings.Fields(lines[idx+2])
			if len(fields) < 5 {
				return windowsCmdRoute{}, errCantParse
			}

			return windowsCmdRoute{
				GW:    fields[2],
				Iface: fields[3],
			}, nil
		}
		if strings.HasPrefix(line, "=======") {
			sep++
			continue
		}
	}
	return windowsCmdRoute{}, errNoGateway
}
