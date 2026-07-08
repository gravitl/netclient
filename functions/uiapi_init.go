package functions

import (
	"github.com/gravitl/netclient/uiapi"
)

func init() {
	uiapi.SetHandlers(uiapi.HandlerDeps{
		RegisterSession:     RegisterSession,
		ReleaseSession:      ReleaseSession,
		Connect:             connectWithJoin,
		Disconnect:          Disconnect,
		IsRegistered:        IsRegisteredToServer,
		FetchNetworks:       fetchNetworksForUI,
		JoinNetwork:         joinNetworkForUI,
		LeaveNetwork:        leaveNetworkForUI,
		CancelJoin:          cancelJoinForUI,
		RequestJIT:          requestJITForUI,
		Sync:                SyncDeviceWithServer,
		ListExitNodes:       listExitNodesForUI,
		GetSelectedExitNode: getSelectedExitNodeForUI,
		SelectExitNode:      selectExitNodeForUI,
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

func listExitNodesForUI(network, server, token string) ([]uiapi.DeviceExitNodeView, error) {
	nodes, err := ListDeviceExitNodes(network, token)
	if err != nil {
		return nil, err
	}
	out := make([]uiapi.DeviceExitNodeView, len(nodes))
	for i, n := range nodes {
		out[i] = uiapi.DeviceExitNodeView{
			EgressID:        n.EgressID,
			Name:            n.Name,
			Description:     n.Description,
			Network:         n.Network,
			RoutingNodeID:   n.RoutingNodeID,
			RoutingHostName: n.RoutingHostName,
			Selected:        n.Selected,
			Status:          n.Status,
		}
	}
	return out, nil
}

func getSelectedExitNodeForUI(network, server, token string) (*uiapi.DeviceExitNodeView, error) {
	node, err := GetDeviceSelectedExitNode(network, token)
	if err != nil || node == nil {
		return nil, err
	}
	view := uiapi.DeviceExitNodeView{
		EgressID:        node.EgressID,
		Name:            node.Name,
		Description:     node.Description,
		Network:         node.Network,
		RoutingNodeID:   node.RoutingNodeID,
		RoutingHostName: node.RoutingHostName,
		Selected:        node.Selected,
		Status:          node.Status,
	}
	return &view, nil
}

func selectExitNodeForUI(network, server, token, egressID string) (*uiapi.DeviceExitNodeView, error) {
	node, err := SelectDeviceExitNode(network, token, egressID)
	if err != nil || node == nil {
		return nil, err
	}
	view := uiapi.DeviceExitNodeView{
		EgressID:        node.EgressID,
		Name:            node.Name,
		Description:     node.Description,
		Network:         node.Network,
		RoutingNodeID:   node.RoutingNodeID,
		RoutingHostName: node.RoutingHostName,
		Selected:        node.Selected,
		Status:          node.Status,
	}
	return &view, nil
}

func sessionCredentials() (server, token string) {
	return uiapi.SessionCredentials()
}
