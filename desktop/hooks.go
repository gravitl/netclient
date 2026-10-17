package desktop

import (
	"github.com/gravitl/netclient/functions"
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
}
