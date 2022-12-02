package wireguard

// Inspired by https://github.com/paultag/go-modprobe and https://github.com/pmorjan/kmod

import (
	"bufio"
	"errors"
	"fmt"
	"io"

	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/gravitl/netmaker/logger"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	defaultModuleDir        = "/lib/modules"
	tunModulePath           = "/dev/net/tun"
	wireguardMod            = "wireguard"
	tunMod                  = "tun"
	wgTestLink              = "wgtester4"
	procModules             = "/proc/modules"
	unknown          status = iota
	unloaded
	unloading
	loading
	live
	inuse
)

// == types ==

type status int

type kernelModule struct {
	name string
	path string
}

var (
	ErrModuleNotFound = errors.New("module not found")
	moduleLibDir      = defaultModuleDir
	moduleRoot        = getModulesRoot()
)

func getModulesRoot() string {
	uname := unix.Utsname{}
	if err := unix.Uname(&uname); err != nil {
		panic(err)
	}

	i := 0
	for ; uname.Release[i] != 0; i++ {
	}

	return filepath.Join(moduleLibDir, string(uname.Release[:i]))
}

func isTunModuleLoaded() bool {
	_, err := os.Stat(tunModulePath)
	if err == nil {
		return true
	}

	isLoaded, err := modProbe("tun")
	if err != nil {
		logger.Log(0, "failed to load tun module - %v", err.Error())
	}
	return isLoaded
}

func isKernelWireGuardPresent() bool {
	if lazyLoadKernelWireGuard() {
		return true
	}

	loaded, err := modProbe("wireguard")
	if err != nil {
		return false
	}

	return loaded
}

func lazyLoadKernelWireGuard() bool {
	newWGLink := getNewLink(wgTestLink)

	newWGLink.attrs.MTU = math.MaxInt

	err := netlink.LinkAdd(newWGLink)

	return errors.Is(err, syscall.EINVAL)
}

func modProbe(moduleName string) (bool, error) {
	if isModuleEnabled(moduleName) {
		return true, nil
	}
	modulePath, err := getModFullPath(moduleName)
	if err != nil {
		return false, fmt.Errorf("error probing module %s - %v", moduleName, err)
	}
	if modulePath == "" {
		return false, nil
	}

	logger.Log(2, "loading module", moduleName)

	err = loadModuleWithDependencies(moduleName, modulePath)
	if err != nil {
		return false, fmt.Errorf("couldn't load %s module, error: %v", moduleName, err)
	}
	return true, nil
}

func isModuleEnabled(name string) bool {
	builtin, builtinErr := isBuiltinModule(name)
	state, statusErr := moduleStatus(name)
	return (builtinErr == nil && builtin) || (statusErr == nil && state >= loading)
}

func getModFullPath(name string) (string, error) {
	var foundPath string
	skipRemainingDirs := false

	err := filepath.WalkDir(
		moduleRoot,
		func(path string, info fs.DirEntry, err error) error {
			if skipRemainingDirs {
				return fs.SkipDir
			}
			if err != nil || !info.Type().IsRegular() {
				return nil
			}

			nameFromPath := getNameFromPath(path)
			if nameFromPath == name {
				foundPath = path
				skipRemainingDirs = true
			}

			return nil
		})

	if err != nil {
		return "", err
	}

	return foundPath, nil
}

func getNameFromPath(s string) string {
	s = filepath.Base(s)
	for ext := filepath.Ext(s); len(ext) > 0; ext = filepath.Ext(s) {
		s = strings.TrimSuffix(s, ext)
	}
	return modName(s)
}

func modName(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "-", "_")
}

func isBuiltinModule(name string) (bool, error) {
	f, err := os.Open(filepath.Join(moduleRoot, "/modules.builtin"))
	if err != nil {
		return false, err
	}
	defer func() {
		err := f.Close()
		if err != nil {
			logger.Log(0, "could not close modules.builtin -", err.Error())
		}
	}()

	var found bool
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if getNameFromPath(line) == name {
			found = true
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return found, nil
}

// status types: <Live|Loading|Unloading>
func moduleStatus(name string) (status, error) {
	state := unknown
	f, err := os.Open(procModules)
	if err != nil {
		return state, err
	}
	defer func() {
		err := f.Close()
		if err != nil {
			logger.Log(0, "could not close", procModules, "-", err.Error())
		}
	}()

	state = unloaded

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if fields[0] == name {
			if fields[2] != "0" {
				state = inuse
				break
			}
			switch strings.ToLower(fields[4]) {
			case "live":
				state = live
			case "loading":
				state = loading
			case "unloading":
				state = unloading
			}
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return state, err
	}

	return state, nil
}

func loadModuleWithDependencies(name, path string) error {
	deps, err := getModDependencies(name)
	if err != nil {
		return fmt.Errorf("failed to get dependencies for module %s", name)
	}
	for _, dep := range deps {
		err = load(dep.name, dep.path)
		if err != nil {
			return fmt.Errorf("couldn't load dependecy module %s for %s", dep.name, name)
		}
	}
	return load(name, path)
}

func load(name, path string) error {
	state, err := moduleStatus(name)
	if err != nil {
		return err
	}
	if state >= loading {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		err := f.Close()
		if err != nil {
			logger.Log(0, "could not close", path, "-", err.Error())
		}
	}()

	err = unix.FinitModule(int(f.Fd()), "", 0)
	if errors.Is(err, unix.ENOSYS) {
		buf, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		return unix.InitModule(buf, "")
	}
	return err
}

func getModDependencies(name string) ([]kernelModule, error) {
	f, err := os.Open(filepath.Join(moduleRoot, "/modules.dep"))
	if err != nil {
		return nil, err
	}
	defer func() {
		err := f.Close()
		if err != nil {
			logger.Log(0, "could not close modules.dep -", err.Error())
		}
	}()

	var deps []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if getNameFromPath(strings.TrimSuffix(fields[0], ":")) == name {
			deps = fields
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(deps) == 0 {
		return nil, ErrModuleNotFound
	}
	deps[0] = strings.TrimSuffix(deps[0], ":")

	var modules []kernelModule
	for _, v := range deps {
		if getNameFromPath(v) != name {
			modules = append(modules, kernelModule{
				name: getNameFromPath(v),
				path: filepath.Join(moduleRoot, v),
			})
		}
	}

	return modules, nil
}
