package ncutils

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/gravitl/netmaker/logger"
)

const afUnspec = 0

// interfaceIndexOffset is the byte offset of InterfaceIndex within
// MIB_IPINTERFACE_ROW (netioapi.h): Family (USHORT, offset 0) is followed by
// 6 bytes of padding to satisfy NET_LUID's 8-byte alignment, then
// InterfaceLuid (8 bytes, offset 8), then InterfaceIndex (ULONG, offset 16).
const interfaceIndexOffset = 16

var (
	modIphlpapi                 = syscall.NewLazyDLL("iphlpapi.dll")
	procNotifyIpInterfaceChange = modIphlpapi.NewProc("NotifyIpInterfaceChange")
	procCancelMibChangeNotify2  = modIphlpapi.NewProc("CancelMibChangeNotify2")

	networkChangeNotifyHandle uintptr
	networkChangeCallbackPtr  uintptr

	onNetworkChange func(interfaceName string)
)

// RegisterNetworkChangeHandler registers a function to run whenever an IP
// interface changes state (added, removed, or its parameters change - e.g.
// coming up or going down, gaining/losing an address). This fires
// independently of suspend/resume notifications: it catches network changes
// that happen without any sleep/wake cycle at all (Wi-Fi toggled, cable
// unplugged, hotspot bounced), and also covers cases like Modern Standby
// where the network can stay associated across a real sleep and
// suspend/resume notifications alone wouldn't be enough signal.
//
// onChange receives the name of the interface that changed, resolved on a
// best-effort basis - it's empty if the interface could no longer be looked
// up (most commonly because it was just removed). Callers that create their
// own virtual interfaces (e.g. WireGuard adapters) will see notifications
// for their own interface churn too; onChange is called for every change
// regardless of source, so filtering out self-caused changes is the
// caller's responsibility (this package has no way to know what a caller's
// own interfaces are named).
func RegisterNetworkChangeHandler(onChange func(interfaceName string)) error {
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
func networkChangeCallback(callerContext uintptr, row unsafe.Pointer, notificationType uintptr) uintptr {
	var interfaceName string
	if row != nil {
		index := *(*uint32)(unsafe.Add(row, interfaceIndexOffset))
		if iface, err := net.InterfaceByIndex(int(index)); err == nil {
			interfaceName = iface.Name
		}
	}

	logger.Log(2, fmt.Sprintf("windows network interface change notification received (interface=%q)", interfaceName))
	if onNetworkChange != nil {
		onNetworkChange(interfaceName)
	}
	return 0
}
