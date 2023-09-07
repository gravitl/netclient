// Package ncutils contains utility functions
package ncutils

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/base32"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/c-robinson/iplib"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// MaxNameLength - maximum node name length
const MaxNameLength = 62

// NoDBRecord - error message result
const NoDBRecord = "no result found"

// NoDBRecords - error record result
const NoDBRecords = "could not find any records"

// WindowsSvcName - service name
const WindowsSvcName = "netclient"

// NetclientDefaultPort - default port
const NetclientDefaultPort = 51821

// DefaultGCPercent - garbage collection percent
const DefaultGCPercent = 10

// KeySize = ideal length for keys
const KeySize = 2048

// IsWindows - checks if is windows
func IsWindows() bool {
	return runtime.GOOS == "windows"
}

// IsMac - checks if is a mac
func IsMac() bool {
	return runtime.GOOS == "darwin"
}

// IsLinux - checks if is linux
func IsLinux() bool {
	return runtime.GOOS == "linux"
}

// IsFreeBSD - checks if is freebsd
func IsFreeBSD() bool {
	return runtime.GOOS == "freebsd"
}

// HasWgQuick - checks if WGQuick command is present
func HasWgQuick() bool {
	cmd, err := exec.LookPath("wg-quick")
	return err == nil && cmd != ""
}

// GetWireGuard - checks if wg is installed
func GetWireGuard() string {
	userspace := os.Getenv("WG_QUICK_USERSPACE_IMPLEMENTATION")
	if userspace != "" && (userspace == "boringtun" || userspace == "wireguard-go") {
		return userspace
	}
	return "wg"
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

// IsKernel - checks if running kernel WireGuard
func IsKernel() bool {
	//TODO
	//Replace && true with some config file value
	//This value should be something like kernelmode, which should be 'on' by default.
	return IsLinux() && os.Getenv("WG_QUICK_USERSPACE_IMPLEMENTATION") == ""
}

// IsEmptyRecord - repeat from database
func IsEmptyRecord(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), NoDBRecord) || strings.Contains(err.Error(), NoDBRecords)
}

// GetMacAddr - get's mac address
func GetMacAddr() ([]net.HardwareAddr, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var as []net.HardwareAddr
	for _, ifa := range ifas {
		a := ifa.HardwareAddr
		if a != nil {
			as = append(as, a)
		}
	}
	return as, nil
}

// GetLocalIP - gets local ip of machine
// returns first interface that is up, is not a loopback and is
func GetLocalIP(localrange net.IPNet) (*net.IPNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if i.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if net, ok := addr.(*net.IPNet); ok {
				if localrange.Contains(net.IP) {
					return net, nil
				}
			}
		}
	}
	return nil, errors.New("not found")
}

// GetNetworkIPMask - Pulls the netmask out of the network
func GetNetworkIPMask(networkstring string) (string, string, error) {
	ip, ipnet, err := net.ParseCIDR(networkstring)
	if err != nil {
		return "", "", err
	}
	ipstring := ip.String()
	mask := ipnet.Mask
	maskstring := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
	//maskstring := ipnet.Mask.String()
	return ipstring, maskstring, err
}

// GetFreePort - gets free port of machine
func GetFreePort(rangestart int) (int, error) {
	addr := net.UDPAddr{}
	if rangestart == 0 {
		rangestart = NetclientDefaultPort
	}
	for x := rangestart; x <= 65535; x++ {
		addr.Port = int(x)
		conn, err := net.ListenUDP("udp", &addr)
		if err != nil {
			continue
		}
		defer conn.Close()
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

// GetFreeTCPPort - gets free TCP port
func GetFreeTCPPort() (string, error) {
	addr := net.TCPAddr{
		IP: net.ParseIP("127.0.0.1"),
	}
	conn, err := net.ListenTCP("tcp", &addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	x := strconv.Itoa(conn.Addr().(*net.TCPAddr).Port)
	log.Println("--- free port found: ", x, "---")
	return x, nil
}

// == OS PATH FUNCTIONS ==

// GetHomeDirWindows - gets home directory in windows
func GetHomeDirWindows() string {
	if IsWindows() {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}

// GetSeparator - gets the separator for OS
func GetSeparator() string {
	if IsWindows() {
		return "\\"
	} else {
		return "/"
	}
}

// GetFileWithRetry - retry getting file X number of times before failing
func GetFileWithRetry(path string, retryCount int) ([]byte, error) {
	var data []byte
	var err error
	for count := 0; count < retryCount; count++ {
		data, err = os.ReadFile(path)
		if err == nil {
			return data, err
		} else {
			logger.Log(1, "failed to retrieve file ", path, ", retrying...")
			time.Sleep(time.Second >> 2)
		}
	}
	return data, err
}

func CheckIPAddress(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("ip address %s is invalid", ip)
	}
	return nil
}

// GetNewIface - Gets the name of the real interface created on Mac
func GetNewIface(dir string) (string, error) {
	files, _ := os.ReadDir(dir)
	var newestFile string
	var newestTime int64 = 0
	var err error
	for _, f := range files {
		fi, err := os.Stat(dir + f.Name())
		if err != nil {
			return "", err
		}
		currTime := fi.ModTime().Unix()
		if currTime > newestTime && strings.Contains(f.Name(), ".sock") {
			newestTime = currTime
			newestFile = f.Name()
		}
	}
	resultArr := strings.Split(newestFile, ".")
	if resultArr[0] == "" {
		err = errors.New("sock file does not exist")
	}
	return resultArr[0], err
}

// GetFileAsString - returns the string contents of a given file
func GetFileAsString(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(content), err
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

// RunCmds - runs cmds
func RunCmds(commands []string, printerr bool) error {
	var err error
	for _, command := range commands {
		//prevent panic
		if len(strings.Trim(command, " ")) == 0 {
			continue
		}
		args := strings.Fields(command)
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil && printerr {
			logger.Log(0, "error running command:", command)
			logger.Log(0, strings.TrimSuffix(string(out), "\n"))
		}
	}
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

// GetHostname - Gets hostname of machine
func GetHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	if len(hostname) > MaxNameLength {
		hostname = hostname[0:MaxNameLength]
	}
	return hostname
}

// CheckUID - Checks to make sure user has root privileges
//func CheckUID() {
//	// start our application
//	out, err := RunCmd("id -u", true)
//
//	if err != nil {
//		log.Fatal(out, err)
//	}
//	id, err := strconv.Atoi(string(out[:len(out)-1]))
//
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	if id != 0 {
//		log.Fatal("This program must be run with elevated privileges (sudo). This program installs a SystemD service and configures WireGuard and networking rules. Please re-run with sudo/root.")
//	}
//}

// CheckFirewall - checks if iptables of nft install, if not exit
func CheckFirewall() {
	if !IsIPTablesPresent() && !IsNFTablesPresent() {
		log.Fatal("neither iptables nor nft is installed - please install one or the other and try again")
	}
}

// CheckWG - Checks if WireGuard is installed. If not, exit
func CheckWG() {
	uspace := GetWireGuard()
	if !HasWG() {
		if uspace == "wg" {
			log.Fatal("WireGuard not installed. Please install WireGuard (wireguard-tools) and try again.")
		}
		logger.Log(0, "running with userspace wireguard: ", uspace)
	} else if uspace != "wg" {
		logger.Log(0, "running userspace WireGuard with ", uspace)
	}
}

// HasWG - returns true if wg command exists
func HasWG() bool {
	var _, err = exec.LookPath("wg")
	return err == nil
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

// ServerAddrSliceContains - sees if a string slice contains a string element
func ServerAddrSliceContains(slice []models.ServerAddr, item models.ServerAddr) bool {
	for _, s := range slice {
		if s.Address == item.Address && s.IsLeader == item.IsLeader {
			return true
		}
	}
	return false
}

func GetIPNetFromString(ip string) (net.IPNet, error) {
	var ipnet *net.IPNet
	var err error
	// parsing as a CIDR first. If valid CIDR, append
	if _, cidr, err := net.ParseCIDR(ip); err == nil {
		ipnet = cidr
	} else { // parsing as an IP second. If valid IP, check if ipv4 or ipv6, then append
		if iplib.Version(net.ParseIP(ip)) == 4 {
			ipnet = &net.IPNet{
				IP:   net.ParseIP(ip),
				Mask: net.CIDRMask(32, 32),
			}
		} else if iplib.Version(net.ParseIP(ip)) == 6 {
			ipnet = &net.IPNet{
				IP:   net.ParseIP(ip),
				Mask: net.CIDRMask(128, 128),
			}
		}
	}
	if ipnet == nil {
		err = errors.New(ip + " is not a valid ip or cidr")
		return net.IPNet{}, err
	}
	return *ipnet, err
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

func IPIsPrivate(ipnet net.IP) bool {
	return ipnet.IsPrivate() || ipnet.IsLoopback()
}

// GetInterfaceName - fetches the interface name
func GetInterfaceName() string {
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

// ConvHostPassToHash - converts password to md5 hash
func ConvHostPassToHash(hostPass string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(hostPass)))
}
