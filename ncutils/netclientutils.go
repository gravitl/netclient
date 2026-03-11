// Package ncutils contains utility functions
package ncutils

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/gob"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

var ifaceName string

// NetclientDefaultPort - default port
const NetclientDefaultPort = 51821

// IsWindows - checks if is windows
func IsWindows() bool {
	return runtime.GOOS == "windows"
}

// IsLinux - checks if is linux
func IsLinux() bool {
	return runtime.GOOS == "linux"
}

// IsNFTablesPresent - returns true if nftables is present, false otherwise.
// Does not consider OS, up to the caller to determine if the OS supports nftables/whether this check is valid.
func IsNFTablesPresent() bool {
	found := false
	_, err := exec.LookPath("nft")
	if err == nil {
		found = true
	}
	return found
}

// IsIPTablesPresent - returns true if iptables is present, false otherwise
// Does not consider OS, up to the caller to determine if the OS supports iptables/whether this check is valid.
func IsIPTablesPresent() bool {
	found := false
	_, err := exec.LookPath("iptables")
	if err == nil {
		found = true
	}
	return found
}

// GetMacAddr - get's mac address
func GetMacAddr() ([]net.HardwareAddr, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var as []net.HardwareAddr
	for _, ifa := range ifas {
		if len(ifa.HardwareAddr) > 0 && ifa.Flags&net.FlagLoopback == 0 {
			as = append(as, ifa.HardwareAddr)
		}
	}
	return as, nil
}

// IsPublicIP indicates whether IP is public or not.
func IsPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return false
	}
	return true
}

// getExcludedInterfaces returns a list of interface name patterns to exclude from detection.
// Default exclusions: flannel, cni (K8s CNI interfaces that cause endpoint detection bugs).
// Additional exclusions can be added via NETCLIENT_EXCLUDE_INTERFACES env var (comma-separated).
// Example: NETCLIENT_EXCLUDE_INTERFACES=flannel,cni,calico,weave
func getExcludedInterfaces() []string {
	defaults := []string{"flannel", "cni"}
	envExcludes := os.Getenv("NETCLIENT_EXCLUDE_INTERFACES")
	if envExcludes == "" {
		return defaults
	}
	excludes := strings.Split(envExcludes, ",")
	for i := range excludes {
		excludes[i] = strings.TrimSpace(excludes[i])
	}
	return excludes
}

// isExcludedInterface checks if an interface name matches any excluded pattern
func isExcludedInterface(ifaceName string) bool {
	for _, pattern := range getExcludedInterfaces() {
		if pattern != "" && strings.Contains(ifaceName, pattern) {
			return true
		}
	}
	return false
}

func GetInterfaces() ([]models.Iface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var data = []models.Iface{}
	var link models.Iface
	for _, iface := range ifaces {
		iface := iface
		if iface.Flags&net.FlagUp == 0 || // interface down
			iface.Flags&net.FlagLoopback != 0 || // loopback interface
			iface.Flags&net.FlagPointToPoint != 0 || // avoid direct connections
			iface.Name == GetInterfaceName() || strings.Contains(iface.Name, "netmaker") || // avoid netmaker
			IsBridgeNetwork(iface.Name) || // avoid bridges
			strings.Contains(iface.Name, "docker") || // avoid docker
			isExcludedInterface(iface.Name) { // avoid user-configured interfaces (default: flannel, cni)
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			ip, cidr, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if ip.IsLoopback() || // no need to send loopbacks
				IsPublicIP(ip) { // no need to send public IPs
				continue
			}
			link.Name = iface.Name
			link.Address = *cidr
			link.Address.IP = ip
			data = append(data, link)
		}
	}
	return data, nil
}

// GetFreePort - gets free port of machine
func GetFreePort(rangestart, currListenPort int, init bool) (int, error) {
	if init || currListenPort == 443 {
		// check 443 is free
		udpAddr := net.UDPAddr{
			Port: 443,
		}
		udpConn, udpErr := net.ListenUDP("udp", &udpAddr)
		if udpErr == nil {
			udpConn.Close()
			return 443, nil
		}
	}
	if currListenPort > 0 {
		// check if curr listen port is free
		udpAddr := net.UDPAddr{
			Port: currListenPort,
		}
		udpConn, udpErr := net.ListenUDP("udp", &udpAddr)
		if udpErr == nil {
			udpConn.Close()
			return currListenPort, nil
		}
	}
	if rangestart == 0 {
		rangestart = NetclientDefaultPort
	}
	for x := rangestart; x <= 65535; x++ {
		udpAddr := net.UDPAddr{
			Port: x,
		}
		udpConn, udpErr := net.ListenUDP("udp", &udpAddr)
		if udpErr != nil {
			continue
		}
		udpConn.Close()
		return x, nil
	}
	return rangestart, errors.New("no free ports")
}

// IsPortFree - checks if port is free
func IsPortFree(port int) (free bool) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err == nil {
		free = true
		conn.Close()
	}
	return
}

// Copy - copies a src file to dest
func Copy(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return errors.New(src + " is not a regular file")
	}

	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	if err != nil {
		return err
	}
	err = os.Chmod(dst, 0755)

	return err
}

// FileExists - checks if file exists locally
func FileExists(f string) bool {
	info, err := os.Stat(f)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil && strings.Contains(err.Error(), "not a directory") {
		return false
	}
	if err != nil {
		logger.Log(0, "error reading file: "+f+", "+err.Error())
	}
	return !info.IsDir()
}

// ShortenString - Brings string down to specified length. Stops names from being too long
func ShortenString(input string, length int) string {
	output := input
	if len(input) > length {
		output = input[0:length]
	}
	return output
}

// DNSFormatString - Formats a string with correct usage for DNS
func DNSFormatString(input string) string {
	reg, err := regexp.Compile("[^a-zA-Z0-9-]+")
	if err != nil {
		logger.Log(0, "error with regex: "+err.Error())
		return ""
	}
	return reg.ReplaceAllString(input, "")
}

// ConvertKeyToBytes - util to convert a key to bytes to use elsewhere
func ConvertKeyToBytes(key *[32]byte) ([]byte, error) {
	var buffer bytes.Buffer
	var enc = gob.NewEncoder(&buffer)
	if err := enc.Encode(key); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// ConvertBytesToKey - util to convert bytes to a key to use elsewhere
func ConvertBytesToKey(data []byte) (*[32]byte, error) {
	var buffer = bytes.NewBuffer(data)
	var dec = gob.NewDecoder(buffer)
	var result = new([32]byte)
	var err = dec.Decode(result)
	if err != nil {
		return nil, err
	}
	return result, err
}

func SetInterfaceName(iface string) {
	if runtime.GOOS == "darwin" && !strings.HasPrefix(iface, "utun") {
		return
	}
	ifaceName = iface
}

// GetInterfaceName - fetches the interface name
func GetInterfaceName() string {
	if ifaceName != "" {
		return ifaceName
	}
	if runtime.GOOS == "darwin" {
		return "utun69"
	}
	return "netmaker"
}

// RandomMacAddress returns a random macaddress
func RandomMacAddress() net.HardwareAddr {
	//var mac net.HardwareAddr
	buff := make([]byte, 6)
	if _, err := rand.Read(buff); err != nil {
		logger.Log(0, "error reading buffer, setting macaddress to zeo value", err.Error())
		return net.HardwareAddr{}
	}
	// Set local bit to ensure no clash with globally administered addresses
	buff[0] |= 2
	mac := net.HardwareAddr(buff)
	if _, err := net.ParseMAC(mac.String()); err != nil {
		logger.Log(0, "randommac is not valid mac", err.Error())
		return net.HardwareAddr{}
	}
	return mac
}

// RandomString - returns a random string in a charset
func RandomString(length int) string {
	randombytes := make([]byte, length)
	_, err := rand.Read(randombytes)
	if err != nil {
		logger.Log(0, "random string", err.Error())
		return ""
	}
	return base32.StdEncoding.EncodeToString(randombytes)[:length]
}

// InterfaceExists - checks if iface exists already
func InterfaceExists(ifaceName string) (bool, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false, err
	}
	for _, inet := range interfaces {
		if inet.Name == ifaceName {
			return true, nil
		}
	}
	return false, nil
}

func SetVerbosity(logLevel int) {
	var level slog.Level
	switch logLevel {

	case 0:
		level = slog.LevelError
	case 1:
		level = slog.LevelInfo
	case 2:
		level = slog.LevelWarn
	case 3:
		level = slog.LevelDebug

	default:
		level = slog.LevelError
	}
	// Create the logger with the chosen level
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})
	logger := slog.New(handler)
	slog.SetDefault(logger)

}

func TraceCaller() {
	// Skip 1 frame to get the caller of this function
	pc, file, line, ok := runtime.Caller(2)
	if !ok {
		slog.Debug("Unable to get caller information")
		return
	}
	tracePc, _, _, ok := runtime.Caller(1)
	if !ok {
		slog.Debug("Unable to get caller information")
		return
	}
	traceFuncName := runtime.FuncForPC(tracePc).Name()
	// Get function name from the program counter (pc)
	funcName := runtime.FuncForPC(pc).Name()

	// Print trace details
	slog.Debug("## TRACE -> Called from function: ", "tracing-func-name", traceFuncName, "caller-func-name", funcName)
	slog.Debug("## TRACE -> Caller File Info", "file", file, "line-no", line)
}
