package functions

import (
	"github.com/gravitl/netclient/uiapi"
	"github.com/gravitl/netmaker/models"
)

func init() {
	uiapi.SetHandlers(uiapi.HandlerDeps{
		RegisterSession:           RegisterSession,
		ReleaseSession:            ReleaseSession,
		Connect:                   connectWithJoin,
		Disconnect:                Disconnect,
		IsRegistered:              IsRegisteredToServer,
		FetchNetworks:             FetchDeviceNetworks,
		JoinNetwork:               joinNetworkForUI,
		LeaveNetwork:              leaveNetworkForUI,
		CancelJoin:                cancelJoinForUI,
		RequestJIT:                requestJITForUI,
		Sync:                      SyncDeviceWithServer,
		ListExitNodes:             listExitNodesForUI,
		GetSelectedExitNode:       getSelectedExitNodeForUI,
		SelectExitNode:            selectExitNodeForUI,
		RestoreDesiredConnections: RestoreDesiredConnections,
	})
}

func connectWithJoin(network string) error {
	server, token := sessionCredentials()
	if token != "" {
		return ConnectNetwork(network, server, token)
	}
	return Connect(network)
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

func listExitNodesForUI(network, server, token string) ([]models.DeviceExitNode, error) {
	return ListDeviceExitNodes(network, token)
}

func getSelectedExitNodeForUI(network, server, token string) (*models.DeviceExitNode, error) {
	return GetDeviceSelectedExitNode(network, token)
}

func selectExitNodeForUI(network, server, token, egressID string) (*models.DeviceExitNode, error) {
	return SelectDeviceExitNode(network, token, egressID)
}

func sessionCredentials() (server, token string) {
	return uiapi.SessionCredentials()
}
