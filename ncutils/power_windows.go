package ncutils

import (
	"syscall"
	"unsafe"

	"github.com/gravitl/netmaker/logger"
)

// Power event types delivered to the suspend/resume callback.
// See: https://learn.microsoft.com/en-us/windows/win32/power/system-power-status
const (
	// PBT_APMSUSPEND - the system is about to suspend. Handlers registered for
	// this event must return quickly (Windows gives very little time, on the
	// order of a couple seconds, before suspending regardless) - do only cheap,
	// local work here, not network I/O.
	PBT_APMSUSPEND = 0x4
	// PBT_APMRESUMESUSPEND - the user resumed interaction with the system after the system
	// entered a low-power/suspended state due to user activity (e.g. closing a laptop lid
	// and reopening it).
	PBT_APMRESUMESUSPEND = 0x7
	// PBT_APMRESUMEAUTOMATIC - the system has resumed operation, signaling that the
	// system may have resumed automatically (e.g. from hibernate) without user interaction.
	PBT_APMRESUMEAUTOMATIC = 0x12

	deviceNotifyCallback = 2
)

// deviceNotifySubscribeParameters mirrors DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS.
type deviceNotifySubscribeParameters struct {
	callback uintptr
	context  uintptr
}

var (
	modUser32                               = syscall.NewLazyDLL("user32.dll")
	procRegisterSuspendResumeNotification   = modUser32.NewProc("RegisterSuspendResumeNotification")
	procUnregisterSuspendResumeNotification = modUser32.NewProc("UnregisterSuspendResumeNotification")

	suspendResumeNotifyHandle uintptr
	powerEventCallbackPtr     uintptr

	onSuspend         func()
	onResumeAutomatic func()
	onResumeSuspend   func()
)

// RegisterPowerEventHandlers registers the given functions to run when Windows
// broadcasts PBT_APMSUSPEND (system about to suspend), PBT_APMRESUMEAUTOMATIC
// (system resumed, possibly without user interaction), and PBT_APMRESUMESUSPEND
// (user resumed interaction after suspend). Any handler may be nil to ignore
// that event. Calling this again replaces any previously registered handlers
// and re-registers the notification.
//
// Note: suspend must return quickly - Windows only allows a couple seconds
// before it suspends regardless, so the suspend handler should do cheap,
// local work only, not network I/O.
func RegisterPowerEventHandlers(suspend, resumeAutomatic, resumeSuspend func()) error {
	UnregisterPowerEventHandlers()

	onSuspend = suspend
	onResumeAutomatic = resumeAutomatic
	onResumeSuspend = resumeSuspend

	if powerEventCallbackPtr == 0 {
		powerEventCallbackPtr = syscall.NewCallback(powerEventCallback)
	}

	params := deviceNotifySubscribeParameters{
		callback: powerEventCallbackPtr,
	}

	handle, _, err := procRegisterSuspendResumeNotification.Call(
		uintptr(unsafe.Pointer(&params)),
		uintptr(deviceNotifyCallback),
	)
	if handle == 0 {
		return err
	}
	suspendResumeNotifyHandle = handle
	return nil
}

// UnregisterPowerEventHandlers unregisters any previously registered power
// event handlers and stops delivery of suspend/resume notifications.
func UnregisterPowerEventHandlers() {
	if suspendResumeNotifyHandle != 0 {
		procUnregisterSuspendResumeNotification.Call(suspendResumeNotifyHandle)
		suspendResumeNotifyHandle = 0
	}
	onSuspend = nil
	onResumeAutomatic = nil
	onResumeSuspend = nil
}

// powerEventCallback is invoked by Windows on a system thread when a power
// event occurs. It must match PDEVICE_NOTIFY_CALLBACK_ROUTINE's signature.
func powerEventCallback(context, eventType, setting uintptr) uintptr {
	switch eventType {
	case PBT_APMSUSPEND:
		logger.Log(0, "windows power event: PBT_APMSUSPEND (system suspending)")
		if onSuspend != nil {
			onSuspend()
		}
	case PBT_APMRESUMEAUTOMATIC:
		logger.Log(0, "windows power event: PBT_APMRESUMEAUTOMATIC (system resumed)")
		if onResumeAutomatic != nil {
			onResumeAutomatic()
		}
	case PBT_APMRESUMESUSPEND:
		logger.Log(0, "windows power event: PBT_APMRESUMESUSPEND (user resumed interaction after suspend)")
		if onResumeSuspend != nil {
			onResumeSuspend()
		}
	}
	return 0
}
