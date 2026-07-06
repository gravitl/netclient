package functions

import (
	"github.com/gravitl/netclient/uiapi"
)

func init() {
	uiapi.SetHandlers(uiapi.HandlerDeps{
		RegisterSession: RegisterSession,
		ReleaseSession:  ReleaseSession,
		Connect:         connectWithJoin,
		Disconnect:      Disconnect,
		IsRegistered:    IsRegisteredToServer,
		FetchNetworks:   fetchNetworksForUI,
		JoinNetwork:     joinNetworkForUI,
		LeaveNetwork:    leaveNetworkForUI,
		CancelJoin:      cancelJoinForUI,
		RequestJIT:      requestJITForUI,
		Sync:            SyncDeviceWithServer,
	})
}

func connectWithJoin(network string) error {
	server, token := sessionCredentials()
	if token != "" {
		return ConnectNetwork(network, server, token)
	}
	return Connect(network)
}

func fetchNetworksForUI(server, token string) ([]uiapi.DeviceNetworkView, error) {
	nets, err := FetchDeviceNetworks(server, token)
	if err != nil {
		return nil, err
	}
	out := make([]uiapi.DeviceNetworkView, len(nets))
	for i, n := range nets {
		out[i] = uiapi.DeviceNetworkView{
			NetworkID:           n.NetworkID,
			DisplayName:         n.DisplayName,
			Joined:              n.Joined,
			Connected:           n.Connected,
			Pending:             n.Pending,
			Status:              n.Status,
			ApprovalRequired:    n.ApprovalRequired,
			ApprovalRequestedAt: n.ApprovalRequestedAt,
			JITEnabled:          n.JITEnabled,
			JITAppliesToUser:  n.JITAppliesToUser,
			HasJITAccess:      n.HasJITAccess,
			JITPendingRequest: n.JITPendingRequest,
			JITExpiresAt:      n.JITExpiresAt,
		}
	}
	return out, nil
}

func joinNetworkForUI(network, server, token string) (string, error) {
	status, err := JoinDeviceNetworkOnServer(network, token)
	if err != nil {
		return "", err
	}
	_, _, _, err = PullForDesktop(false, true)
	if err != nil {
		return "", err
	}
	if status == "" {
		return "joined", nil
	}
	return status, nil
}

func leaveNetworkForUI(network, server, token string) error {
	return LeaveDeviceNetworkOnServer(network, token)
}

func cancelJoinForUI(network, server, token string) error {
	return CancelDeviceNetworkJoinOnServer(network, token)
}

func requestJITForUI(network, server, token, reason string) error {
	return RequestJITOnServer(network, token, reason)
}

func sessionCredentials() (server, token string) {
	return uiapi.SessionCredentials()
}
