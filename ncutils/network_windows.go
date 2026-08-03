package ncutils

import (
	"syscall"
	"unsafe"

	"github.com/gravitl/netmaker/logger"
)

const afUnspec = 0

var (
	modIphlpapi                 = syscall.NewLazyDLL("iphlpapi.dll")
	procNotifyIpInterfaceChange = modIphlpapi.NewProc("NotifyIpInterfaceChange")
	procCancelMibChangeNotify2  = modIphlpapi.NewProc("CancelMibChangeNotify2")

	networkChangeNotifyHandle uintptr
	networkChangeCallbackPtr  uintptr

	onNetworkChange func()
)

// RegisterNetworkChangeHandler registers a function to run whenever an IP
// interface changes state (added, removed, or its parameters change - e.g.
// coming up or going down, gaining/losing an address). This fires
// independently of suspend/resume notifications: it catches network changes
// that happen without any sleep/wake cycle at all (Wi-Fi toggled, cable
// unplugged, hotspot bounced), and also covers cases like Modern Standby
// where the network can stay associated across a real sleep and
// suspend/resume notifications alone wouldn't be enough signal.
func RegisterNetworkChangeHandler(onChange func()) error {
	UnregisterNetworkChangeHandler()

	onNetworkChange = onChange

	if networkChangeCallbackPtr == 0 {
		networkChangeCallbackPtr = syscall.NewCallback(networkChangeCallback)
	}

	var handle uintptr
	ret, _, _ := procNotifyIpInterfaceChange.Call(
		uintptr(afUnspec),
		networkChangeCallbackPtr,
		0,
		0, // InitialNotification = FALSE, don't fire once immediately for existing interfaces.
		uintptr(unsafe.Pointer(&handle)),
	)
	if ret != 0 {
		return syscall.Errno(ret)
	}
	networkChangeNotifyHandle = handle
	return nil
}

// UnregisterNetworkChangeHandler unregisters any previously registered
// network change handler.
func UnregisterNetworkChangeHandler() {
	if networkChangeNotifyHandle != 0 {
		procCancelMibChangeNotify2.Call(networkChangeNotifyHandle)
		networkChangeNotifyHandle = 0
	}
	onNetworkChange = nil
}

// networkChangeCallback is invoked by Windows on a system thread whenever an
// IP interface's state changes. It must match
// PIPINTERFACE_CHANGE_CALLBACK's signature.
func networkChangeCallback(callerContext, row, notificationType uintptr) uintptr {
	logger.Log(2, "windows network interface change notification received")
	if onNetworkChange != nil {
		onNetworkChange()
	}
	return 0
}
