package desktop

import (
	"github.com/gravitl/netclient/functions"
	"github.com/gravitl/netclient/uiapi"
)

func init() {
	functions.GUI.PrepareConnect = prepareDesktopConnect
	functions.GUI.RememberConnection = rememberDesiredConnection
	functions.GUI.ForgetConnection = forgetDesiredConnection
	functions.GUI.FinishConnect = finishDesktopConnect
	functions.GUI.FilterPreserved = filterPreservedConnections
	functions.GUI.ReassertDesired = reassertDesiredConnectedFlags
	functions.GUI.WantsIGW = desktopWantsIGW
	functions.GUI.WantsUnadvertisedExit = desktopWantsExitApply
	functions.GUI.RememberWantIGW = rememberDesiredWantIGW
	functions.GUI.ReconcileExit = reconcileDesiredExit
	functions.GUI.ExitDecision = desktopExitDecision
	functions.GUI.ApplyStartup = ApplyDesiredConnectedFlags
	functions.GUI.RefreshHostPull = refreshHostPullAfterReconnect
	functions.GUI.ForgetNetwork = forgetDesiredNetworkOnLeave

	functions.GUI.StartUIAPI = uiapi.Start
	functions.GUI.StopUIAPI = uiapi.Stop
	functions.GUI.RefreshUIAPI = uiapi.Refresh
	functions.GUI.ForceLogout = uiapi.ForceLogout
	functions.GUI.IsSessionActive = uiapi.IsSessionActive
	functions.GUI.EnsureSessionLoaded = uiapi.EnsureSessionLoaded
	functions.GUI.KeepServerDomainForRelogin = func() bool { return true }
}
